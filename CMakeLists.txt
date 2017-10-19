
cmake_minimum_required ( VERSION 2.8.12 )

# project
project ( wilton_http CXX )

# dep options
set ( staticlib_pion_USE_LOG4CPLUS ON CACHE BOOL "Use log4cplus lib for logging" )
set ( staticlib_pion_USE_OPENSSL ON CACHE BOOL "Use OpenSSL lib for https" )

# dependencies add
if ( STATICLIB_TOOLCHAIN MATCHES "windows_[^_]+_[^_]+" )
    staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_openssl )
    staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_curl )
    staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_asio )
elseif ( WILTON_BUILD_FLAVOUR MATCHES "wheezy" )
    staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_asio )
elseif ( WILTON_BUILD_FLAVOUR MATCHES "el7" )
    staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_curl )
endif ( )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_crypto )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_pion )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_http )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_mustache )

# dependencies check
set ( ${PROJECT_NAME}_DEPS
        staticlib_config
        staticlib_support
        staticlib_io
        staticlib_ranges
        staticlib_pion
        staticlib_json
        staticlib_unzip
        staticlib_http
        staticlib_utils
        staticlib_mustache
        staticlib_tinydir
        staticlib_pimpl
        staticlib_crypto
        libcurl
        openssl
        zlib )
staticlib_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# library
set ( ${PROJECT_NAME}_PLATFORM_SRC ) 
set ( ${PROJECT_NAME}_RESFILE )
set ( ${PROJECT_NAME}_DEFFILE )
if ( ${CMAKE_SYSTEM_NAME} STREQUAL "Windows" )
    configure_file ( ${WILTON_DIR}/resources/buildres/wilton_module.rc
            ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.rc )
    set ( ${PROJECT_NAME}_RESFILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.rc )
    set ( ${PROJECT_NAME}_DEFFILE ${CMAKE_CURRENT_LIST_DIR}/resources/${PROJECT_NAME}.def )
    list ( REMOVE_ITEM ${PROJECT_NAME}_DEPS_PC_LIBRARIES log4cplus )
endif ( )

add_library ( ${PROJECT_NAME} SHARED
        # client
        ${CMAKE_CURRENT_LIST_DIR}/src/client/wilton_client.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/client/wiltoncall_client.cpp
        # mustache
        ${CMAKE_CURRENT_LIST_DIR}/src/mustache/wilton_mustache.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/mustache/wiltoncall_mustache.cpp
        # server
        ${CMAKE_CURRENT_LIST_DIR}/src/server/request.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/server/response_writer.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/server/server.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/server/wilton_server.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/server/wiltoncall_server.cpp
        # export
        ${CMAKE_CURRENT_LIST_DIR}/src/wiltoncall_http.cpp
        ${${PROJECT_NAME}_RESFILE}
        ${${PROJECT_NAME}_DEFFILE} )

target_link_libraries ( ${PROJECT_NAME} PRIVATE
        wilton_core
        wilton_logging
        ${${PROJECT_NAME}_DEPS_PC_LIBRARIES} )

target_include_directories ( ${PROJECT_NAME} BEFORE PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/src
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${WILTON_DIR}/core/include
        ${WILTON_DIR}/modules/wilton_logging/include
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )

target_compile_options ( ${PROJECT_NAME} PRIVATE ${${PROJECT_NAME}_DEPS_PC_CFLAGS_OTHER} )

if ( ${CMAKE_SYSTEM_NAME} STREQUAL "Windows" )
    target_link_libraries ( ${PROJECT_NAME} PRIVATE wtsapi32 )
    set_property ( TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "/manifest:no" )
endif ( )

# pkg-config
set ( ${PROJECT_NAME}_PC_CFLAGS "-I${CMAKE_CURRENT_LIST_DIR}/include" )
set ( ${PROJECT_NAME}_PC_LIBS "-L${CMAKE_LIBRARY_OUTPUT_DIRECTORY} -l${PROJECT_NAME}" )
staticlib_list_to_string ( ${PROJECT_NAME}_PC_REQUIRES_PRIVATE "" ${PROJECT_NAME}_DEPS )
configure_file ( ${WILTON_DIR}/resources/buildres/pkg-config.in 
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${PROJECT_NAME}.pc )
