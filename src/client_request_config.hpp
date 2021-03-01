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
 * File:   client_request_config.hpp
 * Author: alex
 *
 * Created on June 13, 2016, 4:24 PM
 */

#ifndef WILTON_CLIENT_CLIENT_REQUEST_CONFIG_HPP
#define WILTON_CLIENT_CLIENT_REQUEST_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "staticlib/http.hpp"
#include "staticlib/ranges.hpp"
#include "staticlib/json.hpp"

#include "wilton/support/exception.hpp"

namespace wilton {
namespace http {

class client_request_config {
public:
    sl::http::request_options options;
    std::string request_data_file_path;
    std::string respone_data_file_path;
    bool respone_data_hex = false;

    client_request_config(const client_request_config&) = delete;

    client_request_config& operator=(const client_request_config&) = delete;

    client_request_config(client_request_config&& other) :
    options(std::move(other.options)),
    request_data_file_path(std::move(other.request_data_file_path)),
    respone_data_file_path(std::move(other.respone_data_file_path)),
    respone_data_hex(other.respone_data_hex) { }

    client_request_config& operator=(client_request_config&& other) {
        this->options = std::move(other.options);
        this->request_data_file_path = std::move(other.request_data_file_path);
        this->respone_data_file_path = std::move(other.respone_data_file_path);
        this->respone_data_hex = other.respone_data_hex;
        return *this;
    }

    client_request_config() { }

    client_request_config(const sl::json::value& json) {
        for (const sl::json::field& fi : json.as_object()) {
            auto& name = fi.name();
            if ("headers" == name) {
                for (const sl::json::field& hf : fi.as_object_or_throw(name)) {
                    std::string val = hf.as_string_nonempty_or_throw(hf.name());
                    options.headers.emplace_back(hf.name(), std::move(val));
                }
            } else if ("method" == name) {
                options.method = fi.as_string_nonempty_or_throw(name);
            } else if ("abortOnConnectError" == name) {
                options.abort_on_connect_error = fi.as_bool_or_throw(name);
            } else if ("abortOnResponseError" == name) {
                options.abort_on_response_error = fi.as_bool_or_throw(name);
            } else if ("maxNumberOfResponseHeaders" == name) {
                options.max_number_of_response_headers = fi.as_uint16_positive_or_throw(name);
            } else if ("consumerThreadWakeupTimeoutMillis" == name) {
                options.consumer_thread_wakeup_timeout_millis = fi.as_uint16_positive_or_throw(name);
            } else if ("forceHttp10" == name) {
                options.force_http_10 = fi.as_bool_or_throw(name);
            } else if ("noprogress" == name) {
                options.noprogress = fi.as_bool_or_throw(name);
            } else if ("nosignal" == name) {
                options.nosignal = fi.as_bool_or_throw(name);
            } else if ("failonerror" == name) {
                options.failonerror = fi.as_bool_or_throw(name);
            } else if ("pathAsIs" == name) {
                options.path_as_is = fi.as_bool_or_throw(name);
            } else if ("tcpNodelay" == name) {
                options.tcp_nodelay = fi.as_bool_or_throw(name);
            } else if ("tcpKeepalive" == name) {
                options.tcp_keepalive = fi.as_bool_or_throw(name);
            } else if ("tcpKeepidleSecs" == name) {
                options.tcp_keepidle_secs = fi.as_uint32_positive_or_throw(name);
            } else if ("tcpKeepintvlSecs" == name) {
                options.tcp_keepintvl_secs = fi.as_uint32_positive_or_throw(name);
            } else if ("connecttimeoutMillis" == name) {
                options.connecttimeout_millis = fi.as_uint32_positive_or_throw(name);
            } else if ("timeoutMillis" == name) {
                options.timeout_millis = fi.as_uint32_positive_or_throw(name);
            } else if ("buffersizeBytes" == name) {
                options.buffersize_bytes = fi.as_uint32_positive_or_throw(name);
            } else if ("acceptEncoding" == name) {
                options.accept_encoding = fi.as_string_nonempty_or_throw(name);
            } else if ("followlocation" == name) {
                options.followlocation = fi.as_bool_or_throw(name);
            } else if ("maxredirs" == name) {
                options.maxredirs = fi.as_uint32_or_throw(name);
            } else if ("useragent" == name) {
                options.useragent = fi.as_string_nonempty_or_throw(name);
            } else if ("maxSentSpeedLargeBytesPerSecond" == name) {
                options.max_sent_speed_large_bytes_per_second = fi.as_uint32_or_throw(name);
            } else if ("maxRecvSpeedLargeBytesPerSecond" == name) {
                options.max_recv_speed_large_bytes_per_second = fi.as_uint32_or_throw(name);
            } else if ("sslcertFilename" == name) {
                options.sslcert_filename = fi.as_string_nonempty_or_throw(name);
            } else if ("sslcertype" == name) {
                options.sslcertype = fi.as_string_nonempty_or_throw(name);
            } else if ("sslkeyFilename" == name) {
                options.sslkey_filename = fi.as_string_nonempty_or_throw(name);
            } else if ("sslKeyType" == name) {
                options.ssl_key_type = fi.as_string_nonempty_or_throw(name);
            } else if ("sslKeypasswd" == name) {
                options.ssl_keypasswd = fi.as_string_nonempty_or_throw(name);
            } else if ("requireTls" == name) {
                options.require_tls = fi.as_bool_or_throw(name);
            } else if ("sslVerifyhost" == name) {
                options.ssl_verifyhost = fi.as_bool_or_throw(name);
            } else if ("sslVerifypeer" == name) {
                options.ssl_verifypeer = fi.as_bool_or_throw(name);
            } else if ("sslVerifystatus" == name) {
                options.ssl_verifystatus = fi.as_bool_or_throw(name);
            } else if ("cainfoFilename" == name) {
                options.cainfo_filename = fi.as_string_nonempty_or_throw(name);
            } else if ("crlfileFilename" == name) {
                options.crlfile_filename = fi.as_string_nonempty_or_throw(name);
            } else if ("sslCipherList" == name) {
                options.ssl_cipher_list = fi.as_string_nonempty_or_throw(name);
            } else if ("queueResponseMaxSizeBytes" == name) {
                options.polling_response_body_max_size_bytes = fi.as_uint32_or_throw(name);
            } else if ("requestDataFilePath" == name) {
                request_data_file_path = fi.as_string_nonempty_or_throw(name);
            } else if ("responseDataFilePath" == name) {
                respone_data_file_path = fi.as_string_nonempty_or_throw(name);
                options.polling_response_body_file_path = std::string(
                        respone_data_file_path.data(), respone_data_file_path.length());
            } else if ("responseDataHex" == name) {
                respone_data_hex = fi.as_bool_or_throw(name);
            } else {
                throw support::exception(TRACEMSG("Unknown 'client_request_config' field: [" + name + "]"));
            }
        }
    }

    sl::json::value to_json() const {
        auto ha = sl::ranges::transform(options.headers, [](const std::pair<std::string, std::string>& el) {
            return sl::json::field{el.first, el.second};
        });
        std::vector<sl::json::field> hfields = sl::ranges::emplace_to_vector(std::move(ha));
        return {
            {"headers", std::move(hfields)},
            {"method", options.method},
            {"abortOnConnectError", options.abort_on_connect_error},
            {"abortOnResponseError", options.abort_on_response_error},
            {"maxNumberOfResponseHeaders", options.max_number_of_response_headers},
            {"consumerThreadWakeupTimeoutMillis", options.consumer_thread_wakeup_timeout_millis},
            {"forceHttp10", options.force_http_10},
            {"noprogress", options.noprogress},
            {"nosignal", options.nosignal},
            {"failonerror", options.failonerror},
            {"pathAsIs", options.path_as_is},
            {"tcpNodelay", options.tcp_nodelay},
            {"tcpKeepalive", options.tcp_keepalive},
            {"tcpKeepidleSecs", options.tcp_keepidle_secs},
            {"tcpKeepintvlSecs", options.tcp_keepintvl_secs},
            {"connecttimeoutMillis", options.connecttimeout_millis},
            {"timeoutMillis", options.timeout_millis},
            {"buffersizeBytes", options.buffersize_bytes},
            {"acceptEncoding", options.accept_encoding},
            {"followlocation", options.followlocation},
            {"maxredirs", options.maxredirs},
            {"useragent", options.useragent},
            {"maxSentSpeedLargeBytesPerSecond", options.max_sent_speed_large_bytes_per_second},
            {"maxRecvSpeedLargeBytesPerSecond", options.max_recv_speed_large_bytes_per_second},
            {"sslcertFilename", options.sslcert_filename},
            {"sslcertype", options.sslcertype},
            {"sslkeyFilename", options.sslkey_filename},
            {"sslKeyType", options.ssl_key_type},
            {"sslKeypasswd", options.ssl_keypasswd},
            {"requireTls", options.require_tls},
            {"sslVerifyhost", options.ssl_verifyhost},
            {"sslVerifypeer", options.ssl_verifypeer},
            {"sslVerifystatus", options.ssl_verifystatus},
            {"cainfoFilename", options.cainfo_filename},
            {"crlfileFilename", options.crlfile_filename},
            {"sslCipherList", options.ssl_cipher_list},
            {"queueResponseMaxSizeBytes", options.polling_response_body_max_size_bytes},

            {"requestDataFilePath", request_data_file_path.empty() },
            {"responseDataFilePath", !respone_data_file_path.empty() ?
                    respone_data_file_path : options.polling_response_body_file_path },
            {"responseDataHex", respone_data_hex}
        };
    }

};

} // namespace
} 

#endif /* WILTON_CLIENT_CLIENT_REQUEST_CONFIG_HPP */

