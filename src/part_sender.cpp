/*
 * Copyright 2018, alex at staticlibs.net
 * Copyright 2018, mike at myasnikov.mike@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>

#include "staticlib/config.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/io/array_source.hpp"
#include "staticlib/io/limited_source.hpp"
#include "staticlib/support.hpp"

#include "wilton/support/exception.hpp"
#include "wilton/support/buffer.hpp"
#include "wilton/wilton_http.h"
#include "wilton/wilton_crypto.h"
#include "client_response.hpp"

#include "part_sender.hpp"

namespace wilton {
namespace http {

namespace {
class wait_timer
{
    std::mutex cond_mtx;
    std::atomic_bool stop_flag;
    std::condition_variable cond;
    std::thread waiter;
    bool is_expired_flag;
public:
    wait_timer() : is_expired_flag(false) {
        this->stop_flag.exchange(false, std::memory_order_acq_rel);
    }
    ~wait_timer() {
        stop();
    }
    bool is_expired() {
        return is_expired_flag;
    }
    void start(int64_t milliseconds){
        is_expired_flag = false;
        waiter = std::thread([this, milliseconds] () {
            this->stop_flag.exchange(false, std::memory_order_acq_rel);
            std::unique_lock<std::mutex> lck(cond_mtx);
            while (!this->stop_flag) {
               std::cv_status status = this->cond.wait_for(lck, std::chrono::milliseconds(milliseconds));
               if (std::cv_status::timeout == status) {
                   this->is_expired_flag = true;
                   break;
               }
            }
        });
    }
    void stop(){
        if (waiter.joinable()) {
            stop_flag.exchange(true, std::memory_order_acq_rel);
            cond.notify_all();
            waiter.join();
        }
    }
};
}

const std::string part_sender::opt_chunk_number{"X-Wilton-FileUpload-ChunkNumber"};
const std::string part_sender::opt_standart_chunk_size{"X-Wilton-FileUpload-ChunksMaxSizeBytes"};
const std::string part_sender::opt_file_name{"X-Wilton-FileUpload-FileName"};
const std::string part_sender::opt_file_size{"X-Wilton-FileUpload-FileSize"};
const std::string part_sender::opt_file_hash256{"X-Wilton-FileUpload-FileHash256"};
const std::string part_sender::opt_chunk_hash256{"X-Wilton-FileUpload-ChunkHash256"};

wilton::http::part_sender::part_sender(staticlib::http::session *http, staticlib::http::request_options options, wilton::http::part_send_options send_options)
    : http(http), options(options), send_options(send_options) {}

size_t wilton::http::part_sender::preapre_file(){
//    std::vector<char> buf(send_options.chunk_max_size);
//    auto sink = sl::io::string_sink();

    // get size
    auto tpath = sl::tinydir::path(send_options.loaded_file_path);
    auto src = tpath.open_read();
    send_options.file_size = src.size(); // get size before move source

    //get hash
    char* out_hash = nullptr;
    int out_hash_len = 0;
    char* err = wilton_crypto_sha256(send_options.loaded_file_path.c_str(),
            static_cast<int>(send_options.loaded_file_path.size()),
            std::addressof(out_hash), std::addressof(out_hash_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    auto deferred = sl::support::defer([out_hash] () STATICLIB_NOEXCEPT {
        wilton_free(out_hash);
    });

    options.headers.push_back(header_option(opt_file_hash256, std::string{out_hash, static_cast<size_t>(out_hash_len)}));

    send_options.chunks_count = send_options.file_size/send_options.chunk_max_size +
            !!(send_options.file_size%send_options.chunk_max_size);
    return send_options.chunks_count;
}

std::string wilton::http::part_sender::send_file(bool& is_timer_expired){
    preapre_file();
    // setup send options
    size_t chunk_number = 0;
    options.headers.push_back(header_option(opt_standart_chunk_size, sl::support::to_string(send_options.chunk_max_size)));
    options.headers.push_back(header_option(opt_file_size, sl::support::to_string(send_options.file_size)));
    options.headers.push_back(header_option(opt_file_name, send_options.file_name));
    options.headers.push_back(header_option(opt_chunk_number, sl::support::to_string(chunk_number)));

    std::vector<sl::json::field> array_value;
    wait_timer timer;
    timer.start(send_options.timeout_ms);
    while(chunk_number < send_options.chunks_count){
        options.headers.back() = (header_option(opt_chunk_number, sl::support::to_string(chunk_number)));
        bool send_continue = false;
        if (timer.is_expired()) {
            sl::json::field expired_field("timer_expired", true);
            array_value.push_back(std::move(expired_field));
            is_timer_expired = true;
            break;
        }
        std::vector<sl::json::value> chunk_send_results;
        do {
            auto tpath = sl::tinydir::path(send_options.loaded_file_path);
            auto source_in = tpath.open_read();
            auto offset = chunk_number*send_options.chunk_max_size;
            source_in.seek(offset);

            auto expected_readed = source_in.size() - offset;
            if (expected_readed > send_options.chunk_max_size) {
                expected_readed = send_options.chunk_max_size;
            }
            options.request_body_content_length = static_cast<uint32_t>(expected_readed);

            auto limited = sl::io::make_limited_source (source_in, expected_readed);

            try{
                auto tmp_resp_resp = http->open_url(send_options.url, std::move(limited), options);
                send_continue = !tmp_resp_resp.connection_successful();
                auto data_hex = std::string{};
                auto dest = sl::io::string_sink();
                {
                    auto sink = sl::io::make_hex_sink(dest);
                    sl::io::copy_all(tmp_resp_resp, sink);
                }
                data_hex = dest.get_string();
                auto resp_json = wilton::http::client_response::to_json(std::move(data_hex),
                        tmp_resp_resp, tmp_resp_resp.get_info());
                chunk_send_results.push_back(std::move(resp_json));
            } catch (const std::exception& e) {
                //supress error on send
                auto msg = std::string{e.what()};
                sl::json::value tmp_val(msg);
                chunk_send_results.push_back(std::move(tmp_val));
                send_continue = true;
            }
            if (timer.is_expired()) {
                break;
            }
        } while (send_continue);
        sl::json::value chunk_result(std::move(chunk_send_results));
        sl::json::field chunk_field(sl::support::to_string(chunk_number), std::move(chunk_result));
        array_value.push_back(std::move(chunk_field));
        ++chunk_number;
    }

    sl::json::value result(std::move(array_value));
    return result.dumps();
}

} // namespace http
} // namespace wilton
