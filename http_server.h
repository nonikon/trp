/*
 * Copyright (C) 2022 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_

#include <stdarg.h>
#include <uv.h>

#ifndef HTTP_SERVER_SAVE_HDR
#define HTTP_SERVER_SAVE_HDR    0   /* save http request header or not */
#endif

#ifndef HTTP_SERVER_TIMEOUT
#define HTTP_SERVER_TIMEOUT     0   // (10 * 1000)  /* (ms) */
#endif

#if HTTP_SERVER_SAVE_HDR
#include "xlist.h"
typedef struct {
    char* field;
    char* value;
    unsigned field_len;
    unsigned value_len;
} http_header_t;
#endif

typedef struct {
#if HTTP_SERVER_SAVE_HDR
    xlist_t headers;    /* http_header_t */
#endif
    char* url;
    char* body;
    unsigned url_len;
    unsigned body_len;
} http_request_t;

typedef struct {
    unsigned header_len;
    unsigned body_len;
    char headers[1024]; /* store HTTP response headers */
    char body[3072];    /* store HTTP response body */
} http_response_t;

typedef struct {
    const char* path;
    void (*cb)(const http_request_t* req, http_response_t* resp);
} http_handler_t;

static inline void http_buf_add_printf(char* buf, unsigned* len, const char* fmt, ...)
{
    va_list arg;
    va_start(arg, fmt);
    *len += vsprintf(buf + *len, fmt, arg);
    va_end(arg);
}

static inline void http_buf_add_string(char* buf, unsigned* len, const char* src)
{
    size_t l = strlen(src);
    memcpy(buf + *len, src, l);
    *len += (unsigned) l;
}

int http_server_start(uv_loop_t* loop, const char* addrstr, const http_handler_t* handlers);

#endif // _HTTP_SERVER_H_