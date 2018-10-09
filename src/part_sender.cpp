#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "staticlib/config.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/io/array_source.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/wilton_http.h"

#include "part_sender.hpp"

namespace wilton {
namespace http {

const std::string part_sender::opt_chunk_number{"X-Wilton-FileUpload-ChunkNumber"};
const std::string part_sender::opt_standart_chunk_size{"X-Wilton-FileUpload-ChunksMaxSizeBytes"};
//const std::string part_sender::opt_chunk_size{"X-Wilton-FileUpload-ChunksSizeBytes"};
const std::string part_sender::opt_file_name{"X-Wilton-FileUpload-FileName"};
const std::string part_sender::opt_file_size{"X-Wilton-FileUpload-FileSize"};

wilton::http::part_sender::part_sender(staticlib::http::session *http, staticlib::http::request_options options, wilton::http::part_send_options send_options)
    : http(http), options(options), send_options(send_options) {}

size_t wilton::http::part_sender::preapre_file(){
    // разделяем файл на части, для этого сначала определим сколько их будет.
    int source = ::open(send_options.loaded_file_path.c_str(), O_RDONLY, 0);
    if (-1 == source) throw support::exception(TRACEMSG("Error opening src file: [" + send_options.loaded_file_path + "]," +
                                                        " error: [" + ::strerror(errno) + "]"));
    auto deferred_src = sl::support::defer([source]() STATICLIB_NOEXCEPT {
                                               ::close(source);
                                           });
    struct stat stat_source;
    auto err_stat = ::fstat(source, std::addressof(stat_source));
    if (-1 == err_stat) throw support::exception(TRACEMSG("Error obtaining file status: [" + send_options.loaded_file_path + "]," +
                                                          " error: [" + ::strerror(errno) + "]"));

    send_options.file_size = stat_source.st_size;
    send_options.chunks_count = send_options.file_size/send_options.chunk_max_size +
            !!(send_options.file_size%send_options.chunk_max_size);
    return send_options.chunks_count;
}

staticlib::http::resource wilton::http::part_sender::send_file(){
    // Усьановить опции отправки.
    size_t chunk_number = 0;
    const size_t last_chunk_number = send_options.chunks_count-1;

    options.headers.push_back(header_option(opt_standart_chunk_size, sl::support::to_string(send_options.chunk_max_size)));
    options.headers.push_back(header_option(opt_file_size, sl::support::to_string(send_options.file_size)));
    options.headers.push_back(header_option(opt_file_name, send_options.file_name));
    options.headers.push_back(header_option(opt_chunk_number, sl::support::to_string(chunk_number)));

    std::vector<sl::http::resource> resp_container;
    while(chunk_number < send_options.chunks_count){
        options.headers.back() = (header_option(opt_chunk_number, sl::support::to_string(chunk_number)));
        bool send_continue = false;
        do {
            auto tpath = sl::tinydir::path(send_options.loaded_file_path);
            auto source_in = tpath.open_read();
            source_in.seek(chunk_number*send_options.chunk_max_size*sizeof(char));
            std::vector<char> buf(send_options.chunk_max_size);
            sl::io::span<char> tmp_span(buf.data(), send_options.chunk_max_size);
            auto readed = source_in.read(tmp_span);
            sl::io::array_source arr_source{tmp_span};

            options.request_body_content_length = static_cast<uint32_t>(readed);
            try{
                auto tmp_resp_resp = http->open_url(send_options.url, std::move(arr_source), options);
                send_continue = !tmp_resp_resp.connection_successful();
                if (chunk_number == last_chunk_number) {
                    resp_container.emplace_back(std::move(tmp_resp_resp));
                }
            } catch (const std::exception& e) {
                //supress error on send
                send_continue = true;
            }
        } while (send_continue);
        ++chunk_number;
    }

    if (!resp_container.size()) {
        throw wilton::support::exception(TRACEMSG("No reasponse at the end"));
    }
    return sl::http::resource(std::move(resp_container[0]));
}

} // namespace http
} // namespace wilton
