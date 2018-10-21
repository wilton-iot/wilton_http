#ifndef WILTON_PART_SENDER_CONFIG
#define WILTON_PART_SENDER_CONFIG

#include <string>
#include "staticlib/http.hpp"
#include "staticlib/json.hpp"
#include "wilton/support/exception.hpp"

namespace wilton {
namespace http {

struct part_send_options{
    // options that depends on user input
    std::string url = "";
    size_t chunks_count = 0;
    size_t file_size = 0;
    std::string loaded_file_path = "";

    // other options, thatnot depends on user input
    size_t chunk_max_size = 102400; // 100 kb
    size_t timeout_ms = 10000; // 10 sec
    std::string file_name = "tmp_file.txt";
};

class part_sender_config
{
public:
    part_send_options options;
    part_sender_config(const sl::json::value& json) {
        for (const sl::json::field& fi : json.as_object()) {
            auto& name = fi.name();
            if ("fileName" == name) {
                options.file_name = fi.as_string_nonempty_or_throw(name);
            } else if ("fullTimeoutMillis" == name) {
                options.timeout_ms = fi.as_uint32_or_throw(name);
            } else if ("maxChunkSize" == name) {
                options.chunk_max_size = fi.as_uint32_or_throw(name);
            } else if ("chunkCount" == name) {
                options.chunks_count = fi.as_uint32_or_throw(name);
            } else if ("fileSize" == name) {
                options.file_size = fi.as_uint32_or_throw(name);
            } else if ("filePath" == name) {
                options.loaded_file_path = fi.as_string_nonempty_or_throw(name);
            } else if ("url" == name) {
                options.url = fi.as_string_nonempty_or_throw(name);
            } else {
                throw support::exception(TRACEMSG("Unknown 'SendOptions' field: [" + name + "]"));
            }
        }
    }
};

} // namespace http
} // namespace wilton

#endif // WILTON_PART_SENDER_CONFIG
