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

#ifndef WILTON_PART_SENDER
#define WILTON_PART_SENDER

#include <string>

#include "part_sender_config.hpp"

namespace wilton {
namespace http {

class part_sender
{
    using header_option = std::pair<std::string, std::string>;
    sl::http::session* http;
    sl::http::request_options options;
    part_send_options send_options;

    static const std::string opt_chunk_number;
    static const std::string opt_standart_chunk_size;
    static const std::string opt_file_name;
    static const std::string opt_file_size;
    static const std::string opt_file_hash256;
    static const std::string opt_chunk_hash256;

public:
    part_sender(sl::http::session* http, sl::http::request_options options, part_send_options send_options);

    size_t preapre_file();
    std::string send_file(bool &is_timer_expired);
};

} // namespace http
} // namespace wilton

#endif // WILTON_PART_SENDER
