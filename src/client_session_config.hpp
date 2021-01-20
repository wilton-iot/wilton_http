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
 * File:   client_session_config.hpp
 * Author: alex
 *
 * Created on June 13, 2016, 4:24 PM
 */

#ifndef WILTON_CLIENT_CLIENT_SESSION_CONFIG_HPP
#define WILTON_CLIENT_CLIENT_SESSION_CONFIG_HPP

#include <cstdint>
#include <string>

#include "staticlib/http.hpp"
#include "staticlib/json.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace http {

class client_session_config {
public:
    bool use_multi_threaded_session = false;
    sl::http::session_options options;

    client_session_config(const client_session_config&) = delete;

    client_session_config& operator=(const client_session_config&) = delete;

    client_session_config(client_session_config&& other) :
    use_multi_threaded_session(other.use_multi_threaded_session),
    options(std::move(other.options)) { }

    client_session_config& operator=(client_session_config&& other) {
        this->use_multi_threaded_session = other.use_multi_threaded_session;
        this->options = std::move(other.options);
        return *this;
    }

    client_session_config() { }

    client_session_config(const sl::json::value& json) {
        // msvs complains to different vectors in foreach here
        auto& vec = json.as_object();
        for (size_t i = 0; i < vec.size(); i++) {
            const sl::json::field& fi = vec[i];
            auto& name = fi.name();
            if ("multiThreaded" == name) {
                this->use_multi_threaded_session = fi.as_bool_or_throw(name);
            } else if ("fdsetTimeoutMillis" == name) {
                this->options.fdset_timeout_millis = fi.as_uint32_positive_or_throw(name);
            } else if ("maxHostConnections" == name) {
                this->options.max_host_connections = fi.as_uint32_positive_or_throw(name);
            } else if ("maxTotalConnections" == name) {
                this->options.max_total_connections = fi.as_uint32_positive_or_throw(name);
            } else if ("maxconnects" == name) {
                this->options.maxconnects = fi.as_uint32_positive_or_throw(name);
            } else {
                throw support::exception(TRACEMSG("Unknown 'ClientSession' field: [" + name + "]"));
            }
        }
    }

    sl::json::value to_json() const {
        return {
            { "multiThreaded", use_multi_threaded_session },
            { "fdsetTimeoutMillis", options.fdset_timeout_millis },
            { "maxHostConnections", options.max_host_connections },
            { "maxTotalConnections", options.max_total_connections },
            { "maxconnects", options.maxconnects }
        };
    }
    
};

} // namespace
} 

#endif /* WILTON_CLIENT_CLIENT_SESSION_CONFIG_HPP */

