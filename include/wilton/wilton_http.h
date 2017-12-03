/* 
 * File:   wilton_db.h
 * Author: alex
 *
 * Created on June 10, 2017, 1:23 PM
 */

#ifndef WILTON_HTTP_H
#define WILTON_HTTP_H

#include "wilton/wilton.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wilton_HttpClient;
typedef struct wilton_HttpClient wilton_HttpClient;

/*
 {
    "requestQueueMaxSize": uint32_t,
    "fdsetTimeoutMillis": uint32_t,
    "allRequestsPausedTimeoutMillis": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLMOPT_MAX_HOST_CONNECTIONS.html
    "maxHostConnections": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLMOPT_MAX_TOTAL_CONNECTIONS.html
    "maxTotalConnections": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLMOPT_MAXCONNECTS.html
    "maxconnects": uint32_t
 }
 */
char* wilton_HttpClient_create(
        wilton_HttpClient** http_out,
        const char* conf_json,
        int conf_json_len);

char* wilton_HttpClient_close(
        wilton_HttpClient* http);

/*

// options implemented manually
 
    "headers": {
        "Header-Name": "header_value",
        ...
    },
    "method": "GET|POST|PUT|DELETE",
    "abortOnConnectError": true,
    "abortOnResponseError": true,
    "maxNumberOfResponseHeaders": uit16_t,
    "consumerThreadWakeupTimeoutMillis": uit16_t,
    "responseDataFilePath": path/to/file,

// general behavior options

    // https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_VERSION.html
    "forceHttp10": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_NOPROGRESS.html
    "noprogress": true,
    // https://curl.haxx.se/libcurl/c/CURLOPT_NOSIGNAL.html
    "nosignal": true,
    // https://curl.haxx.se/libcurl/c/CURLOPT_FAILONERROR.html
    "failonerror": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_PATH_AS_IS.html
    "pathAsIs": true,

// TCP options

    // https://curl.haxx.se/libcurl/c/CURLOPT_TCP_NODELAY.html
    "tcpNodelay": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_TCP_KEEPALIVE.html
    "tcpKeepalive": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_TCP_KEEPIDLE.html
    "tcpKeepidleSecs": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLOPT_TCP_KEEPINTVL.html
    "tcpKeepintvlSecs": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT_MS.html
    "connecttimeoutMillis": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLOPT_TIMEOUT_MS.html
    "timeoutMillis": uint32_t,

// HTTP options

    // https://curl.haxx.se/libcurl/c/CURLOPT_BUFFERSIZE.html 
    "buffersizeBytes": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLOPT_ACCEPT_ENCODING.html
    "acceptEncoding": "gzip",
    // https://curl.haxx.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html
    "followlocation": true,
    // https://curl.haxx.se/libcurl/c/CURLOPT_MAXREDIRS.html
    "maxredirs": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLOPT_USERAGENT.html
    // "Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; GT-I9505 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
    useragent = "";

// throttling options

    // https://curl.haxx.se/libcurl/c/CURLOPT_MAX_SEND_SPEED_LARGE.html
    "maxSentSpeedLargeBytesPerSecond": uint32_t,
    // https://curl.haxx.se/libcurl/c/CURLOPT_MAX_RECV_SPEED_LARGE.html
    "maxRecvSpeedLargeBytesPerSecond": uint32_t,

// SSL options

    // https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERT.html
    "sslcertFilename": "",
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERTTYPE.html
    "sslcertype": "",
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY.html
    "sslkeyFilename": "",
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEYTYPE.html
    "sslKeyType": "",
    // https://curl.haxx.se/libcurl/c/CURLOPT_KEYPASSWD.html
    "sslKeypasswd": "".
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSLVERSION.html
    "requireTls": false.
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html
    "sslVerifyhost": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
    "sslVerifypeer": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYSTATUS.html
    "sslVerifystatus": false,
    // https://curl.haxx.se/libcurl/c/CURLOPT_CAINFO.html
    "cainfoFilename": "",
    // https://curl.haxx.se/libcurl/c/CURLOPT_CRLFILE.html
    "crlfileFilename": "",
    // https://curl.haxx.se/libcurl/c/CURLOPT_SSL_CIPHER_LIST.html
    "sslCipherList": ""
 }
 {    
    // true if connection was successful
    "connectionSuccess": bool,
    "dataHex": "response_data in hex",
    "headers": {
        "Header-Name": "header_value",
        ...
    },
    // https://curl.haxx.se/libcurl/c/CURLINFO_EFFECTIVE_URL.html
    "effectiveUrl": "",
    // https://curl.haxx.se/libcurl/c/CURLINFO_RESPONSE_CODE.html
    "responseCode": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_TOTAL_TIME.html
    "totalTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_NAMELOOKUP_TIME.html
    "namelookupTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_CONNECT_TIME.html
    "connectTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_APPCONNECT_TIME.html
    "appconnectTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_PRETRANSFER_TIME.html
    "pretransferTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_STARTTRANSFER_TIME.html
    "starttransferTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_REDIRECT_TIME.html
    "redirectTimeSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_REDIRECT_COUNT.html
    "redirectCount": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_SPEED_DOWNLOAD.html
    "speedDownloadBytesSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_SPEED_UPLOAD.html
    "speedUploadBytesSecs": double,
    // https://curl.haxx.se/libcurl/c/CURLINFO_HEADER_SIZE.html
    "headerSizeBytes": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_REQUEST_SIZE.html
    "requestSizeBytes": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_SSL_VERIFYRESULT.html
    "sslVerifyresult": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_OS_ERRNO.html
    "osErrno": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_NUM_CONNECTS.html
    "numConnects": long,
    // https://curl.haxx.se/libcurl/c/CURLINFO_PRIMARY_IP.html
    "primaryIp": "",
    // https://curl.haxx.se/libcurl/c/CURLINFO_PRIMARY_PORT.html
    "primaryPort": long,

 }
 */

char* wilton_HttpClient_execute(
        wilton_HttpClient* http,
        const char* url,
        int url_len,
        const char* request_data,
        int request_data_len,
        const char* request_metadata_json,
        int request_metadata_len,
        char** response_data_out,
        int* response_data_len_out);

char* wilton_HttpClient_send_file(
        wilton_HttpClient* http,
        const char* url,
        int url_len,
        const char* file_path,
        int file_path_len,       
        const char* request_metadata_json,
        int request_metadata_len,
        char** response_data_out,
        int* response_data_len_out,
        void* finalizer_ctx,
        void (*finalizer_cb)(
                void* finalizer_ctx,
                int sent_successfully));

#ifdef __cplusplus
}
#endif

#endif /* WILTON_HTTP_H */

