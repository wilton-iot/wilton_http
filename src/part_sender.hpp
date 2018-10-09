#ifndef WILTON_PART_SENDER
#define WILTON_PART_SENDER

#include <string>

#include "staticlib/http.hpp"

namespace wilton {
namespace http {

struct part_send_options{
    size_t chunks_count;
    size_t chunk_max_size;
    size_t file_size;
    std::string file_name;
    std::string loaded_file_path;
    std::string url;
};

class part_sender
{
    using header_option = std::pair<std::string, std::string>;
    sl::http::session* http;
    sl::http::request_options options;
    part_send_options send_options;

    static const std::string opt_chunk_number;
    static const std::string opt_standart_chunk_size;
//    static const std::string opt_chunk_size;
    static const std::string opt_file_name;
    static const std::string opt_file_size;

public:
    part_sender(sl::http::session* http, sl::http::request_options options, part_send_options send_options);

    size_t preapre_file();
    sl::http::resource send_file();
};

} // namespace http
} // namespace wilton

#endif // WILTON_PART_SENDER
