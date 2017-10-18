/* 
 * File:   wiltoncall_http.cpp
 * Author: alex
 *
 * Created on October 18, 2017, 9:16 PM
 */


#include <cstdint>
#include <string>

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"

#include "wilton/support/registrar.hpp"

namespace wilton {

// HttpClient
namespace client {

support::buffer httpclient_send_request(sl::io::span<const char> data);

support::buffer httpclient_send_file(sl::io::span<const char> data);

} // namespace

// Mustache
namespace mustache {

support::buffer mustache_render(sl::io::span<const char> data);

support::buffer mustache_render_file(sl::io::span<const char> data);

} // namespace


// Server
namespace server {

support::buffer server_create(sl::io::span<const char> data);

support::buffer server_stop(sl::io::span<const char> data);

support::buffer request_get_metadata(sl::io::span<const char> data);

support::buffer request_get_data(sl::io::span<const char> data);

support::buffer request_get_form_data(sl::io::span<const char> data);

support::buffer request_get_data_filename(sl::io::span<const char> data);

support::buffer request_set_response_metadata(sl::io::span<const char> data);

support::buffer request_send_response(sl::io::span<const char> data);

support::buffer request_send_temp_file(sl::io::span<const char> data);

support::buffer request_send_mustache(sl::io::span<const char> data);

support::buffer request_send_later(sl::io::span<const char> data);

support::buffer request_send_with_response_writer(sl::io::span<const char> data);

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        // client
        wilton::support::register_wiltoncall("httpclient_send_request", wilton::client::httpclient_send_request);
        wilton::support::register_wiltoncall("httpclient_send_file", wilton::client::httpclient_send_file);
        // server
        wilton::support::register_wiltoncall("server_create", wilton::server::server_create);
        wilton::support::register_wiltoncall("server_stop", wilton::server::server_stop);
        wilton::support::register_wiltoncall("request_get_metadata", wilton::server::request_get_metadata);
        wilton::support::register_wiltoncall("request_get_data", wilton::server::request_get_data);
        wilton::support::register_wiltoncall("request_get_form_data", wilton::server::request_get_form_data);
        wilton::support::register_wiltoncall("request_get_data_filename", wilton::server::request_get_data_filename);
        wilton::support::register_wiltoncall("request_set_response_metadata", wilton::server::request_set_response_metadata);
        wilton::support::register_wiltoncall("request_send_response", wilton::server::request_send_response);
        wilton::support::register_wiltoncall("request_send_temp_file", wilton::server::request_send_temp_file);
        wilton::support::register_wiltoncall("request_send_mustache", wilton::server::request_send_mustache);
        wilton::support::register_wiltoncall("request_send_later", wilton::server::request_send_later);
        wilton::support::register_wiltoncall("request_send_with_response_writer", wilton::server::request_send_with_response_writer);
        // mustache
        wilton::support::register_wiltoncall("mustache_render", wilton::mustache::mustache_render);
        wilton::support::register_wiltoncall("mustache_render_file", wilton::mustache::mustache_render_file);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}
