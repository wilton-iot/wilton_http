/*
 * Copyright 2017, alex at staticlibs.net
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

/* 
 * File:   wilton_client.cpp
 * Author: alex
 * 
 * Created on June 13, 2016, 4:23 PM
 */

#include "wilton/wilton_http.h"

#include <array>
#include <memory>
#include <string>

#include "utf8.h"

#include "staticlib/config.hpp"
#include "staticlib/http.hpp"
#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/tinydir.hpp"

#include "wilton/support/alloc.hpp"
#include "wilton/support/buffer.hpp"
#include "wilton/support/logging.hpp"

#include "client_response.hpp"
#include "client_request_config.hpp"
#include "client_session_config.hpp"
#include "part_sender.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.httpClient");

sl::json::value resp_to_json(wilton::http::client_request_config& opts, sl::http::resource& resp) {
    if (opts.respone_data_file_path.empty()) {
        if (!opts.respone_data_hex) {
            auto dest = sl::io::string_sink();
            sl::io::copy_all(resp, dest);
            auto& str_raw = dest.get_string();
            if (utf8::is_valid(str_raw.begin(), str_raw.end())) {
                return wilton::http::client_response::to_json(
                        std::move(str_raw), resp, resp.get_info());
            } else {
                auto str_utf8 = std::string();
                utf8::replace_invalid(str_raw.begin(), str_raw.end(), std::back_inserter(str_utf8));
                return wilton::http::client_response::to_json(
                        std::move(str_utf8), resp, resp.get_info());
            }
        } else {
            auto dest = sl::io::string_sink();
            {
                auto sink = sl::io::make_hex_sink(dest);
                sl::io::copy_all(resp, sink);
            }
            return wilton::http::client_response::to_json(
                    std::move(dest.get_string()), resp, resp.get_info());
        }
    } else {
        auto sink = sl::tinydir::file_sink(opts.respone_data_file_path);
        sl::io::copy_all(resp, sink);
        auto data_res = sl::json::dumps({
            {"responseDataFilePath", opts.respone_data_file_path}
        });
        return wilton::http::client_response::to_json(
                std::move(data_res), resp, resp.get_info());
    }
}

} // namespace

struct wilton_HttpClient {
private:
    std::unique_ptr<sl::http::session> delegate;

public:
    wilton_HttpClient(sl::http::multi_threaded_session&& delegate) :
    delegate(new sl::http::multi_threaded_session(std::move(delegate))) { }

    wilton_HttpClient(sl::http::single_threaded_session&& delegate) :
    delegate(new sl::http::single_threaded_session(std::move(delegate))) { }

    sl::http::session& impl() {
        return *delegate;
    }
};

struct wilton_HttpQueue {
private:
    std::unique_ptr<sl::http::polling_session> delegate;

public:
    wilton_HttpQueue(sl::http::polling_session&& delegate) :
    delegate(new sl::http::polling_session(std::move(delegate))) { }

    sl::http::polling_session& impl() {
        return *delegate;
    }
};

char* wilton_HttpClient_create(wilton_HttpClient** http_out,
        const char* conf_json, int conf_json_len) /* noexcept */ {
    if (nullptr == http_out) return wilton::support::alloc_copy(TRACEMSG("Null 'http_out' parameter specified"));
    if (nullptr == conf_json) return wilton::support::alloc_copy(TRACEMSG("Null 'conf_json' parameter specified"));
    if (!sl::support::is_uint32_positive(conf_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'conf_json_len' parameter specified: [" + sl::support::to_string(conf_json_len) + "]"));
    try {
        uint32_t conf_json_len_u32 = static_cast<uint32_t> (conf_json_len);
        std::string json_str{conf_json, conf_json_len_u32};
        sl::json::value json = sl::json::loads(json_str);
        wilton::http::client_session_config conf{std::move(json)};
        wilton_HttpClient* http_ptr = nullptr;
        if (conf.use_multi_threaded_session) {
            http_ptr = new wilton_HttpClient(sl::http::multi_threaded_session(std::move(conf.options)));
        } else {
            http_ptr = new wilton_HttpClient(sl::http::single_threaded_session(std::move(conf.options)));
        }
        *http_out = http_ptr;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpClient_close(wilton_HttpClient* http) /* noexcept */ {
    if (nullptr == http) return wilton::support::alloc_copy(TRACEMSG("Null 'http' parameter specified"));
    try {
        delete http;
        std::string suppress_c4702;
        (void) suppress_c4702;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpClient_execute(wilton_HttpClient* http, const char* url, int url_len,
        const char* request_data,int request_data_len,
        const char* request_metadata_json, int request_metadata_len,
        char** response_data_out, int* response_data_len_out) /* noexcept */ {
    if (nullptr == http) return wilton::support::alloc_copy(TRACEMSG("Null 'http' parameter specified"));
    if (nullptr == url) return wilton::support::alloc_copy(TRACEMSG("Null 'url' parameter specified"));
    if (!sl::support::is_uint32_positive(url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'url_len' parameter specified: [" + sl::support::to_string(url_len) + "]"));
    if (!sl::support::is_uint32(request_data_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'request_data_len' parameter specified: [" + sl::support::to_string(request_data_len) + "]"));
    if (!sl::support::is_uint32(request_metadata_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'request_metadata_len' parameter specified: [" + sl::support::to_string(request_metadata_len) + "]"));
    if (nullptr == response_data_out) return wilton::support::alloc_copy(TRACEMSG("Null 'response_data_out' parameter specified"));
    if (nullptr == response_data_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'response_data_len_out' parameter specified"));
    try {
        auto url_str = std::string(url, static_cast<uint32_t> (url_len));
        auto opts_json = sl::json::value();
        if (request_metadata_len > 0) {
            opts_json = sl::json::load({request_metadata_json, request_metadata_len});
        }
        wilton::support::log_debug(logger, "Performing HTTP request, URL: [" + url_str + "]," +
                " options: [" + opts_json.dumps() + "] ...");
        auto opts = wilton::http::client_request_config(std::move(opts_json));
        sl::http::resource resp = [&] {
            if (request_data_len > 0) {
                auto reqlen_u32 = static_cast<uint32_t> (request_data_len);
                auto data_src = sl::io::array_source(request_data, reqlen_u32);
                // do not use chunked post, as length is known
                opts.options.send_request_body_content_length = true;
                opts.options.request_body_content_length = reqlen_u32;
                // POST will be used by default for this API call
                return http->impl().open_url(url_str, std::move(data_src), opts.options);
            } else {
                // GET will be used by default for this API call
                return http->impl().open_url(url_str, opts.options);
            }
        }();
        wilton::support::log_debug(logger,
                "HTTP request complete, status code: [" + sl::support::to_string(resp.get_status_code()) + "]");
        auto resp_complete = resp_to_json(opts, resp);
        auto span = wilton::support::make_json_buffer(resp_complete);
        *response_data_out = span.data();
        *response_data_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpClient_send_file(wilton_HttpClient* http, const char* url, int url_len,
        const char* file_path,int file_path_len,
        const char* request_metadata_json, int request_metadata_len,
        char** response_data_out, int* response_data_len_out,
        void* finalizer_ctx,
        void (*finalizer_cb)(
                void* finalizer_ctx,
                int sent_successfully)) /* noexcept */ {
    if (nullptr == http) return wilton::support::alloc_copy(TRACEMSG("Null 'http' parameter specified"));
    if (nullptr == url) return wilton::support::alloc_copy(TRACEMSG("Null 'url' parameter specified"));
    if (!sl::support::is_uint32_positive(url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'url_len' parameter specified: [" + sl::support::to_string(url_len) + "]"));
    if (nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
    if (!sl::support::is_uint16_positive(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    if (!sl::support::is_uint32(request_metadata_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'request_metadata_len' parameter specified: [" + sl::support::to_string(request_metadata_len) + "]"));
    if (nullptr == response_data_out) return wilton::support::alloc_copy(TRACEMSG("Null 'response_data_out' parameter specified"));
    if (nullptr == response_data_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'response_data_len_out' parameter specified"));
    try {
        auto url_str = std::string(url, static_cast<uint32_t> (url_len));
        auto file_path_str = std::string(file_path, static_cast<uint32_t> (file_path_len));
        auto opts_json = sl::json::value();
        if (request_metadata_len > 0) {
            std::string meta_str{request_metadata_json, static_cast<uint32_t> (request_metadata_len)};
            opts_json = sl::json::loads(meta_str);
        }
        wilton::support::log_debug(logger, "Sending file over HTTP, URL: [" + url_str + "]," +
                " file: [" + file_path_str + "], options: [" + opts_json.dumps() + "] ...");
        wilton::http::client_request_config opts{std::move(opts_json)};
        auto fd = sl::tinydir::file_source(file_path_str);
        // do not use chunked post, as length is known
        opts.options.send_request_body_content_length = true;
        opts.options.request_body_content_length = static_cast<uint32_t>(fd.size());
        sl::http::resource resp = http->impl().open_url(url_str, std::move(fd), opts.options);
        wilton::support::log_debug(logger,
                "HTTP file send complete, status code: [" + sl::support::to_string(resp.get_status_code()) + "]");
        auto resp_complete = resp_to_json(opts, resp);
        if (nullptr != finalizer_cb) {
            finalizer_cb(finalizer_ctx, 1);
        }
        auto span = wilton::support::make_json_buffer(resp_complete);
        *response_data_out = span.data();
        *response_data_len_out = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        if (nullptr != finalizer_cb) {
            finalizer_cb(finalizer_ctx, 0);
        }
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }   
}

char* wilton_HttpClient_send_file_by_parts(wilton_HttpClient* http, const char* url, int url_len,
        const char* file_path, int file_path_len,
        const char* file_send_options_json, int file_send_options_json_len,
        const char* request_metadata_json, int request_metadata_len,
        char** response_data_out, int* response_data_len_out,
        void* finalizer_ctx,
        void (*finalizer_cb)(
                void* finalizer_ctx,
                int sent_successfully)) /* noexcept */ {
    if (nullptr == http) return wilton::support::alloc_copy(TRACEMSG("Null 'http' parameter specified"));
    if (nullptr == url) return wilton::support::alloc_copy(TRACEMSG("Null 'url' parameter specified"));
    if (nullptr == file_send_options_json) return wilton::support::alloc_copy(TRACEMSG("Null 'sendOptions' parameter specified"));
    if (!sl::support::is_uint32_positive(url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'url_len' parameter specified: [" + sl::support::to_string(url_len) + "]"));
    if (nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
    if (!sl::support::is_uint16_positive(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    if (!sl::support::is_uint32(request_metadata_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'request_metadata_len' parameter specified: [" + sl::support::to_string(request_metadata_len) + "]"));
    if (!sl::support::is_uint32(file_send_options_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_send_options_json_len' parameter specified: [" + sl::support::to_string(file_send_options_json_len) + "]"));
    if (nullptr == response_data_out) return wilton::support::alloc_copy(TRACEMSG("Null 'response_data_out' parameter specified"));
    if (nullptr == response_data_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'response_data_len_out' parameter specified"));
    try {
        auto url_str = std::string(url, static_cast<uint32_t> (url_len));
        auto file_path_str = std::string(file_path, static_cast<uint32_t> (file_path_len));
        auto opts_json = sl::json::value();
        if (request_metadata_len > 0) {
            std::string meta_str{request_metadata_json, static_cast<uint32_t> (request_metadata_len)};
            opts_json = sl::json::loads(meta_str);
        }
        auto file_send_opts_json = sl::json::value();
        if (file_send_options_json_len > 0) {
            std::string file_send_opts_str{file_send_options_json, static_cast<uint32_t> (file_send_options_json_len)};
            file_send_opts_json = sl::json::loads(file_send_opts_str);
        }
        wilton::http::client_request_config opts{std::move(opts_json)};
        wilton::http::part_sender_config send_opts{std::move(file_send_opts_json)};
        wilton::support::log_debug(logger, "Sending file over HTTP, URL: [" + url_str + "]," +
                " file: [" + file_path_str + "], metadata: [" + opts_json.dumps() +
                "], send options" + file_send_opts_json.dumps() + "] ...");

        // setup repeated parameters if they not setted
        if (send_opts.options.loaded_file_path.empty()) send_opts.options.loaded_file_path = file_path_str;
        if (send_opts.options.url.empty()) send_opts.options.url = url_str;

        wilton::http::part_sender sender(&http->impl(), opts.options, send_opts.options);
        bool timer_expired = false;
        std::string resp_complete = sender.send_file(timer_expired);
        if (timer_expired) {
            wilton::support::log_debug(logger,
                "HTTP file send NOT complete, timer status: timer expired");
        } else {
            wilton::support::log_debug(logger,
                "HTTP file send complete, timer status: timer NOT expired");
        }
        if (nullptr != finalizer_cb) {
            finalizer_cb(finalizer_ctx, 1);
        }
        *response_data_out = wilton::support::alloc_copy(resp_complete);
        *response_data_len_out = static_cast<int>(resp_complete.length());
        return nullptr;
    } catch (const std::exception& e) {
        if (nullptr != finalizer_cb) {
            finalizer_cb(finalizer_ctx, 0);
        }
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpQueue_create(wilton_HttpQueue** queue_out,
        const char* conf_json, int conf_json_len) /* noexcept */ {
    if (nullptr == queue_out) return wilton::support::alloc_copy(TRACEMSG("Null 'queue_out' parameter specified"));
    if (nullptr == conf_json) return wilton::support::alloc_copy(TRACEMSG("Null 'conf_json' parameter specified"));
    if (!sl::support::is_uint32_positive(conf_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'conf_json_len' parameter specified: [" + sl::support::to_string(conf_json_len) + "]"));
    try {
        uint32_t conf_json_len_u32 = static_cast<uint32_t> (conf_json_len);
        std::string json_str{conf_json, conf_json_len_u32};
        sl::json::value json = sl::json::loads(json_str);
        wilton::support::log_debug(logger, "Creating HTTP Queue, options: [" + json.dumps() + "] ...");
        wilton::http::client_session_config conf{std::move(json)};
        wilton_HttpQueue* queue_ptr = new wilton_HttpQueue(sl::http::polling_session(std::move(conf.options)));
        wilton::support::log_debug(logger, "Queue created successfully");
        *queue_out = queue_ptr;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpQueue_close(wilton_HttpQueue* queue) /* noexcept */ {
    if (nullptr == queue) return wilton::support::alloc_copy(TRACEMSG("Null 'queue' parameter specified"));
    try {
        delete queue;
        std::string suppress_c4702;
        (void) suppress_c4702;
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpQueue_submit(wilton_HttpQueue* queue, const char* url, int url_len,
        const char* request_data, int request_data_len,
        const char* request_metadata_json, int request_metadata_len) /* noexcept */ {
    if (nullptr == queue) return wilton::support::alloc_copy(TRACEMSG("Null 'queue' parameter specified"));
    if (nullptr == url) return wilton::support::alloc_copy(TRACEMSG("Null 'url' parameter specified"));
    if (!sl::support::is_uint32_positive(url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'url_len' parameter specified: [" + sl::support::to_string(url_len) + "]"));
    if (!sl::support::is_uint32(request_data_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'request_data_len' parameter specified: [" + sl::support::to_string(request_data_len) + "]"));
    if (!sl::support::is_uint32(request_metadata_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'request_metadata_len' parameter specified: [" + sl::support::to_string(request_metadata_len) + "]"));
    try {
        auto url_str = std::string(url, static_cast<uint32_t> (url_len));
        auto opts_json = sl::json::value();
        if (request_metadata_len > 0) {
            opts_json = sl::json::load({request_metadata_json, request_metadata_len});
        }
        wilton::support::log_debug(logger, "Submitting HTTP request, URL: [" + url_str + "]," +
                " options: [" + opts_json.dumps() + "] ...");
        auto opts = wilton::http::client_request_config(std::move(opts_json));
        if (request_data_len > 0) {
            auto reqlen_u32 = static_cast<uint32_t> (request_data_len);
            auto data_src = sl::io::string_source(std::string(request_data, reqlen_u32));
            // do not use chunked post, as length is known
            opts.options.send_request_body_content_length = true;
            opts.options.request_body_content_length = reqlen_u32;
            // POST will be used by default for this API call
            auto res_empty = queue->impl().open_url(url_str, std::move(data_src), opts.options);
            (void) res_empty;
        } else {
            // GET will be used by default for this API call
            auto res_empty = queue->impl().open_url(url_str, opts.options);
            (void) res_empty;
        }
        wilton::support::log_debug(logger, "HTTP request enqueued");
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_HttpQueue_poll(wilton_HttpQueue* http,
        char** response_list_json_out, int* response_list_json_len_out) /* noexcept */ {
    if (nullptr == response_list_json_out) return wilton::support::alloc_copy(TRACEMSG(
            "Null 'response_list_json_out' parameter specified"));
    if (nullptr == response_list_json_len_out) return wilton::support::alloc_copy(TRACEMSG(
            "Null 'response_list_json_len_out' parameter specified"));
    try {
        wilton::support::log_debug(logger, "Polling HTTP Queue ...");
        // todo: add a timeout and a loop here
        auto vec = http->impl().poll();
        auto list = std::vector<sl::json::value>();
        // todo: fixme
        auto opts = wilton::http::client_request_config();
        // end: fixme
        for (auto& res : vec) {
            auto json = resp_to_json(opts, res);
            list.emplace_back(std::move(json));
        }
        auto json = sl::json::value(std::move(list));
        auto span = wilton::support::make_json_buffer(json);
        *response_list_json_out = span.data();
        *response_list_json_len_out= span.size_int();
        wilton::support::log_debug(logger, "HTTP request enqueued");
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }

}