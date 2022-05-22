/*
 * Copyright (C) 2021-2022 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <uv.h>

#include "http_parser.h"
#include "common.h"
#include "xlog.h"
#include "xlist.h"

#ifndef HTTP_SERVER_SAVE_HDR
#define HTTP_SERVER_SAVE_HDR    0   /* save http request header or not */
#endif

#ifndef HTTP_SERVER_TIMEOUT
#define HTTP_SERVER_TIMEOUT     0   // (10 * 1000)  /* (ms) */
#endif

#if HTTP_SERVER_SAVE_HDR
typedef struct {
    char* field;
    char* value;
    unsigned field_len;
    unsigned value_len;
} http_hdr_t;
#endif

typedef struct {
    uv_tcp_t io;
#if HTTP_SERVER_TIMEOUT > 0
    uv_timer_t timer;
#endif
    http_parser parser;
#if HTTP_SERVER_SAVE_HDR
    xlist_t headers;    /* http_hdr_t */
#endif
    char* url;
    char* body;
    unsigned url_len;
    unsigned body_len;
    char buf[4096];     /* store HTTP request headers and body */
    unsigned buf_len;
} http_req_t;

typedef struct {
    uv_write_t wreq;    /* write request for 'uv_write()' */
    char headers[1024]; /* store HTTP response headers */
    char body[3072];    /* store HTTP response body */
    unsigned header_len;
    unsigned body_len;
} http_resp_t;

static uv_tcp_t io_server;
static xlist_t requests;  /* http_req_t */
static xlist_t responses; /* http_resp_t */

static void on_write(uv_write_t* req, int status)
{
    xlist_erase(&responses, xlist_value_iter(req->data));
}

static void buf_add_printf(char* buf, unsigned* len, const char* fmt, ...)
{
    va_list arg;

    va_start(arg, fmt);
    *len += vsprintf(buf + *len, fmt, arg);
    va_end(arg);
}

static void buf_add_string(char* buf, unsigned* len, const char* src)
{
    unsigned l = (unsigned) strlen(src);

    memcpy(buf + *len, src, l);
    *len += l;
}

static void handle_request_index(http_req_t* req, http_resp_t* resp)
{
    buf_add_string(resp->headers, &resp->header_len, "Content-Type: text/plain\r\n");
    buf_add_string(resp->body, &resp->body_len, "Hello World!");
}

static void send_page(http_req_t* req, void (*handle_request)(http_req_t*, http_resp_t*))
{
    http_resp_t* resp = xlist_alloc_back(&responses);
    uv_buf_t vbuf[2];

    resp->wreq.data = resp;
    resp->body_len = 0;
    resp->header_len = 0;

    buf_add_printf(resp->headers, &resp->header_len,
            "HTTP/%d.%d 200 OK\r\n"
            "Server: uv-server/1.0\r\n"
            "Connection: %s\r\n",
                req->parser.http_major,
                req->parser.http_minor,
                http_should_keep_alive(&req->parser) ? "keep-alive" : "close");
    handle_request(req, resp);
    buf_add_printf(resp->headers, &resp->header_len,
        "Content-Length: %d\r\n\r\n", resp->body_len);

    vbuf[0].base = resp->headers;
    vbuf[0].len  = resp->header_len;
    vbuf[1].base = resp->body;
    vbuf[1].len  = resp->body_len;

    uv_write(&resp->wreq, (uv_stream_t*) &req->io, vbuf, 2, on_write);
}

static void send_error_page(http_req_t* req, int code, const char* reason)
{
    uv_buf_t vbuf[2];
    http_resp_t* resp = xlist_alloc_back(&responses);

    resp->wreq.data = resp;
    resp->body_len = 0;
    resp->header_len = 0;

    buf_add_string(resp->body, &resp->body_len, reason);
    buf_add_printf(resp->headers, &resp->header_len,
            "HTTP/%d.%d %d %s\r\n"
            "Server: uv-server/1.0\r\n"
            "Connection: %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n\r\n",
                req->parser.http_major,
                req->parser.http_minor,
                code,
                reason,
                http_should_keep_alive(&req->parser) ? "keep-alive" : "close",
                resp->body_len);

    vbuf[0].base = resp->headers;
    vbuf[0].len  = resp->header_len;
    vbuf[1].base = resp->body;
    vbuf[1].len  = resp->body_len;

    uv_write(&resp->wreq, (uv_stream_t*) &req->io, vbuf, 2, on_write);
}

static int on_http_begin(http_parser* parser)
{
    http_req_t* req = parser->data;

    req->url = NULL;
    req->body = NULL;
    req->url_len = 0;
    req->body_len = 0;

#if HTTP_SERVER_SAVE_HDR
    xlist_clear(&req->headers);
#endif
    return 0;
}

static int on_http_url(http_parser* parser, const char* at, size_t length)
{
    http_req_t* req = parser->data;

    if (!req->url)
        req->url = (char*) at;
    req->url_len += (unsigned) length;
    return 0;
}

#if HTTP_SERVER_SAVE_HDR
static int on_http_field(http_parser* parser, const char* at, size_t length)
{
    http_req_t* req = parser->data;
    http_hdr_t* hdr = xlist_back(&req->headers);

    if (xlist_empty(&req->headers) || hdr->value != NULL) {
        hdr = xlist_alloc_back(&req->headers);
        hdr->field = (char*) at;
        hdr->value = NULL;
        hdr->field_len = (unsigned) length;
    } else {
        hdr->field_len += (unsigned) length;
    }
    return 0;
}

static int on_http_value(http_parser* parser, const char* at, size_t length)
{
    http_req_t* req = parser->data;
    http_hdr_t* hdr = xlist_back(&req->headers);

    /* no need to check whether 'hdr' is valid. */
    if (!hdr->value) {
        hdr->value = (char*) at;
        hdr->value_len = (unsigned) length;
    } else {
        hdr->value_len += (unsigned) length;
    }
    return 0;
}

static void dump_headers(http_req_t* req)
{
    xlist_iter_t i = xlist_begin(&req->headers);

    while (i != xlist_end(&req->headers)) {
        http_hdr_t* h = xlist_iter_value(i);

        h->field[h->field_len] = '\0';
        h->value[h->value_len] = '\0';
        xlog_debug("%s: %s", h->field, h->value);

        i = xlist_iter_next(i);
    }
}
#endif // HTTP_SERVER_SAVE_HDR

static int on_http_body(http_parser* parser, const char* at, size_t length)
{
    http_req_t* req = parser->data;

    if (!req->body)
        req->body = (char*) at;
    else if (req->body + req->body_len != at)
        memmove(req->body + req->body_len, at, length); /* chunk body */

    req->body_len += (unsigned) length;
    return 0;
}

static int on_http_complete(http_parser* parser)
{
    http_parser_pause(parser, 1);
    return 0;
}

static const http_parser_settings g_parser_settings = {
    .on_message_begin = on_http_begin,
    .on_url = on_http_url,
#if HTTP_SERVER_SAVE_HDR
    .on_header_field = on_http_field,
    .on_header_value = on_http_value,
#endif
    .on_body = on_http_body,
    .on_message_complete = on_http_complete,
};

static void on_read_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    http_req_t* req = handle->data;

    buf->base = req->buf + req->buf_len;
    buf->len = sizeof(req->buf) - req->buf_len;
}

static void on_closed(uv_handle_t* handle)
{
    http_req_t* req = handle->data;

#if HTTP_SERVER_SAVE_HDR
    xlist_destroy(&req->headers);
#endif
    xlist_erase(&requests, xlist_value_iter(req));

    xlog_debug("%zu requests and %zu responses left.",
        xlist_size(&requests), xlist_size(&responses));
}

static void inline close_connection(http_req_t* req)
{
    uv_close((uv_handle_t*) &req->io, on_closed);
#if HTTP_SERVER_TIMEOUT > 0
    /* 'timer' with NULL 'close_cb' MUST be closed after 'client'. */
    uv_close((uv_handle_t*) &req->timer, NULL);
#endif
}

static void on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf)
{
    http_req_t* req = client->data;

    if (nread > 0) {
        req->buf_len += (unsigned) nread;
        xlog_debug("%zd bytes from client.", nread);

        if (req->buf_len < sizeof(req->buf)) {
            http_parser_execute(&req->parser, &g_parser_settings, buf->base, nread);
#if HTTP_SERVER_TIMEOUT > 0
            uv_timer_again(&req->timer);
#endif
            if (HTTP_PARSER_ERRNO(&req->parser) == HPE_PAUSED) {
                req->url[req->url_len] = '\0';
                xlog_debug("request url [%s].", req->url);
#if HTTP_SERVER_SAVE_HDR
                dump_headers(req);
#endif
                if (!strcmp(req->url, "/")) {
                    send_page(req, handle_request_index);
                } else {
                    send_error_page(req, 404, "Not Found");
                }
                /* uv_timer_stop() and uv_read_stop() when download file, TODO */

                if (http_should_keep_alive(&req->parser)) {
                    http_parser_pause(&req->parser, 0);
                    req->buf_len = 0; /* ignore the following data. */
                } else {
                    close_connection(req);
                }
            } else if (HTTP_PARSER_ERRNO(&req->parser) != HPE_OK) {
                send_error_page(req, 400, "Bad Request");
                /* unset parser error state. */
                http_parser_init(&req->parser, HTTP_REQUEST);
                req->buf_len = 0;
            }
        } else {
            send_error_page(req, 413, "Payload Too Large");
            /* reset parser state. */
            http_parser_init(&req->parser, HTTP_REQUEST);
            req->buf_len = 0;
        }

    } else if (nread < 0) {
        xlog_debug("client disconnected: %s.", uv_err_name((int) nread));
        close_connection(req);
    }

    /* do nothing when nread == 0. */
}

#if HTTP_SERVER_TIMEOUT > 0
static void on_timeout(uv_timer_t* timer)
{
    http_req_t* req = timer->data;

    xlog_debug("request timeout, close.");
    close_connection(req);
}
#endif

static void on_connect(uv_stream_t* server, int status)
{
    http_req_t* req;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }
    req = xlist_alloc_back(&requests);

    uv_tcp_init(server->data, &req->io);
    http_parser_init(&req->parser, HTTP_REQUEST);
#if HTTP_SERVER_SAVE_HDR
    xlist_init(&req->headers, sizeof(http_hdr_t), NULL);
#endif
    req->io.data = req;
    req->parser.data = req;
    req->buf_len = 0;

    if (uv_accept(server, (uv_stream_t*) &req->io) == 0) {
        xlog_debug("http client connected.");
        uv_read_start((uv_stream_t*) &req->io, on_read_alloc, on_read);
#if HTTP_SERVER_TIMEOUT > 0
        req->timer.data = req;
        uv_timer_init(server->data, &req->timer);
        uv_timer_start(&req->timer, on_timeout, HTTP_SERVER_TIMEOUT,
            HTTP_SERVER_TIMEOUT);
#endif
    } else {
        xlog_error("uv_accept failed.");
        uv_close((uv_handle_t*) &req->io, on_closed);
    }
}

int http_server_start(uv_loop_t* loop, const char* str)
{
    union { struct sockaddr x; struct sockaddr_in6 d; } addr;
    int error;

    if (parse_ip_str(str, DEF_CSERVER_PORT, &addr.x) != 0) {
        xlog_error("invalid control server address [%s].", str);
        return -1;
    }
    uv_tcp_init(loop, &io_server);
    uv_tcp_bind(&io_server, &addr.x, 0);

    error = uv_listen((uv_stream_t*) &io_server, LISTEN_BACKLOG, on_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", addr_to_str(&addr), uv_strerror(error));
        uv_close((uv_handle_t*) &io_server, NULL);
        return -1;
    }
    io_server.data = loop;

    xlist_init(&requests, sizeof(http_req_t), NULL);
    xlist_init(&responses, sizeof(http_resp_t), NULL);

    xlog_info("control server (HTTP) listen at [%s].", addr_to_str(&addr));
    return 0;
}
