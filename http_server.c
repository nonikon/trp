/*
 * Copyright (C) 2021-2022 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>

#include "http_server.h"
#include "http_parser.h"
#include "common.h"
#include "xlist.h"
#include "xlog.h"

typedef struct {
    uv_write_t wreq;
    http_response_t pub;
} http_resp_pri_t;

typedef struct {
    uv_tcp_t io;
#if HTTP_SERVER_TIMEOUT > 0
    uv_timer_t timer;
#endif
    http_parser parser;
    http_request_t pub;
    unsigned buf_len;
    char buf[4096];     /* store HTTP request headers and body */
} http_req_pri_t;

static uv_tcp_t __ioserver;
static const http_handler_t* __handlers;
static xlist_t __requests;  /* http_req_pri_t */
static xlist_t __responses; /* http_resp_pri_t */

static void on_write(uv_write_t* req, int status)
{
    xlist_erase(&__responses, xlist_value_iter(req->data));
}

static void send_page(http_req_pri_t* req, const http_handler_t* handler)
{
    uv_buf_t vbuf[2];
    http_resp_pri_t* resp = xlist_alloc_back(&__responses);

    resp->wreq.data = resp;
    resp->pub.body_len = 0;
    resp->pub.header_len = 0;

    http_buf_add_printf(resp->pub.headers, &resp->pub.header_len,
            "HTTP/%d.%d 200 OK\r\n"
            "Server: uv-server/1.0\r\n"
            "Connection: %s\r\n",
                req->parser.http_major,
                req->parser.http_minor,
                http_should_keep_alive(&req->parser) ? "keep-alive" : "close");
    handler->cb(&req->pub, &resp->pub);
    http_buf_add_printf(resp->pub.headers, &resp->pub.header_len,
        "Content-Length: %d\r\n\r\n", resp->pub.body_len);

    vbuf[0].base = resp->pub.headers;
    vbuf[0].len  = resp->pub.header_len;
    vbuf[1].base = resp->pub.body;
    vbuf[1].len  = resp->pub.body_len;

    uv_write(&resp->wreq, (uv_stream_t*) &req->io, vbuf, 2, on_write);
}

static void send_error_page(http_req_pri_t* req, int code, const char* reason)
{
    uv_buf_t vbuf[2];
    http_resp_pri_t* resp = xlist_alloc_back(&__responses);

    resp->wreq.data = resp;
    resp->pub.body_len = 0;
    resp->pub.header_len = 0;

    http_buf_add_string(resp->pub.body, &resp->pub.body_len, reason);
    http_buf_add_printf(resp->pub.headers, &resp->pub.header_len,
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
                resp->pub.body_len);

    vbuf[0].base = resp->pub.headers;
    vbuf[0].len  = resp->pub.header_len;
    vbuf[1].base = resp->pub.body;
    vbuf[1].len  = resp->pub.body_len;

    uv_write(&resp->wreq, (uv_stream_t*) &req->io, vbuf, 2, on_write);
}

static int on_http_begin(http_parser* parser)
{
    http_req_pri_t* req = parser->data;

    req->pub.url = NULL;
    req->pub.body = NULL;
    req->pub.url_len = 0;
    req->pub.body_len = 0;

#if HTTP_SERVER_SAVE_HDR
    xlist_clear(&req->pub.headers);
#endif
    return 0;
}

static int on_http_url(http_parser* parser, const char* at, size_t length)
{
    http_req_pri_t* req = parser->data;

    if (!req->pub.url)
        req->pub.url = (char*) at;
    req->pub.url_len += (unsigned) length;
    return 0;
}

#if HTTP_SERVER_SAVE_HDR
static int on_http_field(http_parser* parser, const char* at, size_t length)
{
    http_req_pri_t* req = parser->data;
    http_header_t* hdr = xlist_back(&req->pub.headers);

    if (xlist_empty(&req->pub.headers) || hdr->value != NULL) {
        hdr = xlist_alloc_back(&req->pub.headers);
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
    http_req_pri_t* req = parser->data;
    http_header_t* hdr = xlist_back(&req->pub.headers);

    /* no need to check whether 'hdr' is valid. */
    if (!hdr->value) {
        hdr->value = (char*) at;
        hdr->value_len = (unsigned) length;
    } else {
        hdr->value_len += (unsigned) length;
    }
    return 0;
}

static void dump_headers(http_req_pri_t* req)
{
    xlist_iter_t i = xlist_begin(&req->pub.headers);

    while (i != xlist_end(&req->pub.headers)) {
        http_header_t* h = xlist_iter_value(i);

        h->field[h->field_len] = '\0';
        h->value[h->value_len] = '\0';
        xlog_debug("%s: %s", h->field, h->value);

        i = xlist_iter_next(i);
    }
}
#endif // HTTP_SERVER_SAVE_HDR

static int on_http_body(http_parser* parser, const char* at, size_t length)
{
    http_req_pri_t* req = parser->data;

    if (!req->pub.body)
        req->pub.body = (char*) at;
    else if (req->pub.body + req->pub.body_len != at)
        memmove(req->pub.body + req->pub.body_len, at, length); /* chunk body */

    req->pub.body_len += (unsigned) length;
    return 0;
}

static int on_http_complete(http_parser* parser)
{
    http_parser_pause(parser, 1);
    return 0;
}

static const http_parser_settings __parser_settings = {
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
    http_req_pri_t* req = handle->data;

    buf->base = req->buf + req->buf_len;
    buf->len = sizeof(req->buf) - req->buf_len;
}

static void on_closed(uv_handle_t* handle)
{
    http_req_pri_t* req = handle->data;

#if HTTP_SERVER_SAVE_HDR
    xlist_destroy(&req->pub.headers);
#endif
    xlist_erase(&__requests, xlist_value_iter(req));

    xlog_debug("%zu requests and %zu responses left.",
        xlist_size(&__requests), xlist_size(&__responses));
}

static void inline close_connection(http_req_pri_t* req)
{
    uv_close((uv_handle_t*) &req->io, on_closed);
#if HTTP_SERVER_TIMEOUT > 0
    /* 'timer' with NULL 'close_cb' MUST be closed after 'client'. */
    uv_close((uv_handle_t*) &req->timer, NULL);
#endif
}

static void on_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf)
{
    http_req_pri_t* req = client->data;

    if (nread > 0) {
        req->buf_len += (unsigned) nread;
        xlog_debug("%zd bytes from client.", nread);

        if (req->buf_len < sizeof(req->buf)) {
            http_parser_execute(&req->parser, &__parser_settings, buf->base, nread);
#if HTTP_SERVER_TIMEOUT > 0
            uv_timer_again(&req->timer);
#endif
            if (HTTP_PARSER_ERRNO(&req->parser) == HPE_PAUSED) {
                const http_handler_t* h = __handlers;

                req->pub.url[req->pub.url_len] = '\0';
                xlog_debug("request url [%s].", req->pub.url);
#if HTTP_SERVER_SAVE_HDR
                dump_headers(req);
#endif
                while (h->path) {
                    if (!strcmp(req->pub.url, h->path)) {
                        send_page(req, h);
                        break;
                    }
                    ++h;
                }
                if (!h->path) {
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
    http_req_pri_t* req = timer->data;

    xlog_debug("request timeout, close.");
    close_connection(req);
}
#endif

static void on_connect(uv_stream_t* server, int status)
{
    http_req_pri_t* req;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }
    req = xlist_alloc_back(&__requests);

    uv_tcp_init(server->data, &req->io);
    http_parser_init(&req->parser, HTTP_REQUEST);
#if HTTP_SERVER_SAVE_HDR
    xlist_init(&req->pub.headers, sizeof(http_header_t), NULL);
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

int http_server_start(uv_loop_t* loop, const char* addrstr, const http_handler_t* handlers)
{
    union { struct sockaddr x; struct sockaddr_in6 d; } addr;
    int error;

    if (parse_ip_str(addrstr, DEF_CSERVER_PORT, &addr.x) != 0) {
        xlog_error("invalid control server address [%s].", addrstr);
        return -1;
    }
    uv_tcp_init(loop, &__ioserver);
    uv_tcp_bind(&__ioserver, &addr.x, 0);

    error = uv_listen((uv_stream_t*) &__ioserver, 1024, on_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", addr_to_str(&addr), uv_strerror(error));
        uv_close((uv_handle_t*) &__ioserver, NULL);
        return -1;
    }
    __ioserver.data = loop;
    __handlers = handlers;

    xlist_init(&__requests, sizeof(http_req_pri_t), NULL);
    xlist_init(&__responses, sizeof(http_resp_pri_t), NULL);

    xlog_info("control server (HTTP) listen at [%s].", addr_to_str(&addr));
    return 0;
}
