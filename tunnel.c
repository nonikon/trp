/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>
#ifndef _WIN32
#include <unistd.h> /* for daemon() */
#include <signal.h> /* for signal() */
#endif
#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#endif

#include "common.h"
#include "xlog.h"
#include "xlist.h"
#include "crypto.h"

#define KEEPIDLE_TIME       (40) /* s */

/*  --------------         ---------------         --------------
 * | proxy-server | <---> | tunnel-server | <---> | applications |
 *  --------------         ---------------         --------------
 *                         (proxy-client)
 */

typedef struct {
    uv_tcp_t io_tclient;    /* tunnel-client */
    uv_tcp_t io_xserver;    /* proxy-server */
#ifdef __linux__
    struct sockaddr_in dest_addr;
#endif
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t ref_count;         /* increase when 'io_xserver' or 'io_tclient' opened, decrease when closed */
    u8_t tclient_blocked;
    u8_t xserver_blocked;
} tserver_ctx_t;

typedef struct {
    uv_write_t wreq;
    char buffer[MAX_SOCKBUF_SIZE - sizeof(uv_write_t)];
} io_buf_t;

static uv_loop_t* loop;

static struct sockaddr_in xserver_addr;
static struct sockaddr_in tunnel_addr;
static xlist_t tserver_ctxs;/* client_ctx_t */
static xlist_t io_buffers;  /* io_buf_t */
static xlist_t conn_reqs;   /* uv_connect_t */

static crypto_t crypto;
static crypto_t cryptox;
static u8_t crypto_key[16];
static u8_t cryptox_key[16];
static u8_t device_id[DEVICE_ID_SIZE];

static void on_xserver_write(uv_write_t* req, int status);
static void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_tclient_write(uv_write_t* req, int status);
static void on_tclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

static void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);

    buf->base = iob->buffer;
    buf->len = sizeof(iob->buffer);
}

static void on_io_closed(uv_handle_t* handle)
{
    tserver_ctx_t* ctx = handle->data;

    if (ctx->ref_count > 1) {
        --ctx->ref_count;
    } else {
        xlist_erase(&tserver_ctxs, xlist_value_iter(ctx));

        xlog_debug("current %zd ctxs, %zd iobufs.",
            xlist_size(&tserver_ctxs), xlist_size(&io_buffers));
    }
}

static void on_xserver_write(uv_write_t* req, int status)
{
    tserver_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->tclient_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_xserver) == 0) {
        xlog_debug("proxy server write queue cleared.");

        /* proxy server write queue cleared, start reading from tunnel client. */
        uv_read_start((uv_stream_t*) &ctx->io_tclient,
            on_iobuf_alloc, on_tclient_read);
        ctx->tclient_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    tserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from proxy server, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        cryptox.decrypt(&ctx->dctx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_tclient,
            &wbuf, 1, on_tclient_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_tclient) > MAX_WQUEUE_SIZE) {
            xlog_debug("tunnel client write queue pending.");

            /* stop reading from proxy server until tunnel client write queue cleared. */
            uv_read_stop(stream);
            ctx->xserver_blocked = 1;
        }

        /* don't release 'iob' in this place,
         *'on_tclient_write' callback will do it.
         */
    } else if (nread < 0) {
        xlog_debug("disconnected from proxy server: %s.", uv_err_name(nread));

        uv_close((uv_handle_t*) stream, on_io_closed);
        uv_close((uv_handle_t*) &ctx->io_tclient, on_io_closed);

        if (buf->base) {
            /* 'buf->base' may be 'NULL' when 'nread' < 0. */
            xlist_erase(&io_buffers, xlist_value_iter(iob));
        }

    } else {
        xlist_erase(&io_buffers, xlist_value_iter(iob));
    }
}

static void on_tclient_write(uv_write_t* req, int status)
{
    tserver_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xserver_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_tclient) == 0) {
        xlog_debug("tunnel client write queue cleared.");

        /* tunnel client write queue cleared, start reading from proxy server. */
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
        ctx->xserver_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_tclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    tserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from tunnel client, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
            &wbuf, 1, on_xserver_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_xserver) > MAX_WQUEUE_SIZE) {
            xlog_debug("proxy server write queue pending.");

            /* stop reading from tunnel client until proxy server write queue cleared. */
            uv_read_stop(stream);
            ctx->tclient_blocked = 1;
        }

        /* don't release 'iob' in this place,
         *'on_xserver_write' callback will do it.
         */
    } else if (nread < 0) {
        xlog_debug("disconnected from tunnel client: %s.", uv_err_name(nread));

        uv_close((uv_handle_t*) stream, on_io_closed);
        uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);

        if (buf->base) {
            /* 'buf->base' may be 'NULL' when 'nread' < 0. */
            xlist_erase(&io_buffers, xlist_value_iter(iob));
        }

    } else {
        xlist_erase(&io_buffers, xlist_value_iter(iob));
    }
}

static void send_connect_cmd(tserver_ctx_t* ctx)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);
    u8_t* pbuf = (u8_t*) iob->buffer;
    cmd_t* cmd;
    uv_buf_t wbuf;
    u8_t dnonce[16];

    if (is_valid_devid(device_id)) {
        /* generate and prepend iv in the first packet */
        rand_bytes(pbuf, MAX_NONCE_LEN);

        cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

        cmd->tag = CMD_TAG;
        cmd->major = VERSION_MAJOR;
        cmd->minor = VERSION_MINOR;
        cmd->cmd = CMD_CONNECT_CLIENT;

        memcpy(cmd->d.devid, device_id, DEVICE_ID_SIZE);

        crypto.init(&ctx->ectx, crypto_key, pbuf);
        crypto.encrypt(&ctx->ectx, (u8_t*) cmd, sizeof(cmd_t));

        pbuf += MAX_NONCE_LEN + sizeof(cmd_t);
    }

    /* generate and prepend iv in the first packet */
    rand_bytes(pbuf, MAX_NONCE_LEN);

    cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

    cmd->tag = CMD_TAG;
    cmd->major = VERSION_MAJOR;
    cmd->minor = VERSION_MINOR;
    cmd->cmd = CMD_CONNECT_IPV4;

#ifdef __linux__
    if (!tunnel_addr.sin_family) {
        cmd->i.port = ctx->dest_addr.sin_port;
        memcpy(cmd->i.addr, &ctx->dest_addr.sin_addr, 4);
    } else {
#endif
        cmd->i.port = tunnel_addr.sin_port;
        memcpy(cmd->i.addr, &tunnel_addr.sin_addr, 4);
#ifdef __linux__
    }
#endif

    memcpy(dnonce, pbuf, MAX_NONCE_LEN);
    convert_nonce(dnonce);

    cryptox.init(&ctx->ectx, cryptox_key, pbuf);
    cryptox.init(&ctx->dctx, cryptox_key, dnonce);
    cryptox.encrypt(&ctx->ectx, (u8_t*) cmd, sizeof(cmd_t));

    wbuf.base = iob->buffer;
    wbuf.len = pbuf + MAX_NONCE_LEN + sizeof(cmd_t) - (u8_t*) iob->buffer;

    iob->wreq.data = ctx;

    uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
        &wbuf, 1, on_xserver_write);
}

static void on_xserver_connected(uv_connect_t* req, int status)
{
    tserver_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_error("connect proxy server failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before proxy server connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->io_tclient, on_io_closed);
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        // }

    } else {
        xlog_debug("proxy server connected.");

        uv_read_start((uv_stream_t*) &ctx->io_tclient,
            on_iobuf_alloc, on_tclient_read);
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
        /* enable tcp-keepalive. */
        uv_tcp_keepalive(&ctx->io_xserver, 1, KEEPIDLE_TIME);

        send_connect_cmd(ctx);
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static int connect_xserver(tserver_ctx_t* ctx)
{
    uv_connect_t* req = xlist_alloc_back(&conn_reqs);

    xlog_debug("connecting porxy server [%s:%d]...",
        inet_ntoa(xserver_addr.sin_addr), ntohs(xserver_addr.sin_port));

    req->data = ctx;
    /* 'io_xserver' will be opened, increase refcount. */
    ++ctx->ref_count;

    if (uv_tcp_connect(req, &ctx->io_xserver,
            (struct sockaddr*) &xserver_addr, on_xserver_connected) != 0) {
        xlog_error("connect proxy server failed immediately.");

        uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        xlist_erase(&conn_reqs, xlist_value_iter(req));
        return -1;
    }

    return 0;
}

static void on_tclient_connect(uv_stream_t* stream, int status)
{
    tserver_ctx_t* ctx;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }

    ctx = xlist_alloc_back(&tserver_ctxs);

    uv_tcp_init(loop, &ctx->io_tclient);

    ctx->io_tclient.data = ctx;
    ctx->io_xserver.data = ctx;
    ctx->ref_count = 1;
    ctx->tclient_blocked = 0;
    ctx->xserver_blocked = 0;

    if (uv_accept(stream, (uv_stream_t*) &ctx->io_tclient) == 0) {
        xlog_debug("a tunnel client connected.");

#ifdef __linux__
        if (!tunnel_addr.sin_family) {
            socklen_t socklen = sizeof(ctx->dest_addr);

            if (getsockopt(ctx->io_tclient.io_watcher.fd, SOL_IP, SO_ORIGINAL_DST,
                    &ctx->dest_addr, &socklen) != 0) {
                xlog_warn("getsockopt SO_ORIGINAL_DST failed.");

                uv_close((uv_handle_t*) &ctx->io_tclient, on_io_closed);
                return;
            }
        }
#endif
        uv_tcp_init(loop, &ctx->io_xserver);

        if (connect_xserver(ctx) != 0) {
            /* connect failed immediately, just close this connection. */
            uv_close((uv_handle_t*) &ctx->io_tclient, on_io_closed);
        }

    } else {
        xlog_error("uv_accept failed.");

        uv_close((uv_handle_t*) &ctx->io_tclient, on_io_closed);
    }
}

int main(int argc, char** argv)
{
    uv_tcp_t io_tserver;
    struct sockaddr_in taddr;
    const char* xserver_str = "127.0.0.1";
    const char* tserver_str = "127.0.0.1";
    const char* tunnel_str = NULL;
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int verbose = 0;
    int error, i;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-x")) {
            if (++i < argc) xserver_str = argv[i];
        } else if (!strcmp(argv[i], "-b")) {
            if (++i < argc) tserver_str = argv[i];
        } else if (!strcmp(argv[i], "-t")) {
            if (++i < argc) tunnel_str = argv[i];
        } else if (!strcmp(argv[i], "-d")) {
            if (++i < argc) devid_str = argv[i];
        } else if (!strcmp(argv[i], "-m")) {
            if (++i < argc) method = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-M")) {
            if (++i < argc) methodx = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-k")) {
            if (++i < argc) passwd = argv[i];
        } else if (!strcmp(argv[i], "-K")) {
            if (++i < argc) passwdx = argv[i];
        } else if (!strcmp(argv[i], "-L")) {
            if (++i < argc) logfile = argv[i];
        } else if (!strcmp(argv[i], "-v")) {
            verbose = 1;
        } else {
            // usage, TODO
            fprintf(stderr, "wrong args.\n");
            return 1;
        }
    }

#ifndef _WIN32
    if (logfile) daemon(1, 0);
    signal(SIGPIPE, SIG_IGN);
#endif

    loop = uv_default_loop();

    seed_rand((u32_t) time(NULL));

    if (xlog_init(logfile) != 0) {
        fprintf(stderr, "open logfile failed.\n");
    }
    xlog_ctrl(verbose ? XLOG_DEBUG : XLOG_INFO, 0, 0);

    uv_tcp_init(loop, &io_tserver);

    if (devid_str && str_to_devid(device_id, devid_str) != 0) {
        xlog_error("invalid device id string [%s].", devid_str);
        goto end;
    }

    if (passwd) {
        derive_key(crypto_key, passwd);
    } else {
        xlog_info("password not set, disable crypto with proxy server.");
        method = CRYPTO_NONE;
    }
    if (devid_str) {
        if (passwdx) {
            derive_key(cryptox_key, passwdx);
        } else {
            xlog_info("PASSWORD (-K) not set, disable crypto with client.");
            methodx = CRYPTO_NONE;
        }
    } else {
        if (passwdx) {
            xlog_info("device id not set, ignore PASSWORD (-K).");
        }
        methodx = method;
        memcpy(cryptox_key, crypto_key, 16);
    }

    if (crypto_init(&crypto, method) != 0) {
        xlog_error("invalid crypto method: %d.", method);
        goto end;
    }
    if (crypto_init(&cryptox, methodx) != 0) {
        xlog_error("invalid crypto METHOD: %d.", methodx);
        goto end;
    }

    if (parse_ip4_str(xserver_str, DEF_XSERVER_PORT, &xserver_addr) != 0) {
        xlog_error("invalid proxy server address [%s].", xserver_str);
        goto end;
    }

    if (parse_ip4_str(tserver_str, DEF_TSERVER_PORT, &taddr) != 0) {
        xlog_error("invalid tunnel server address [%s].", tserver_str);
        goto end;
    }

    if (!tunnel_str) {
#ifdef __linux__
        xlog_info("enter transparent proxy mode.");
#else
        xlog_error("tunnel address must be specified on !linux.");
        goto end;
#endif
    } else if (parse_ip4_str(tunnel_str, -1, &tunnel_addr) != 0) {
        xlog_error("invalid tunnel address [%s].", tunnel_str);
        goto end;
    } else {
        xlog_info("tunnel to [%s:%d].",
            inet_ntoa(tunnel_addr.sin_addr), ntohs(tunnel_addr.sin_port));
    }

    uv_tcp_bind(&io_tserver, (struct sockaddr*) &taddr, 0);

    error = uv_listen((uv_stream_t*) &io_tserver,
                LISTEN_BACKLOG, on_tclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", xserver_str,
            uv_strerror(error));
        goto end;
    }

    xlist_init(&tserver_ctxs, sizeof(tserver_ctx_t), NULL);
    xlist_init(&io_buffers, sizeof(io_buf_t), NULL);
    xlist_init(&conn_reqs, sizeof(uv_connect_t), NULL);

    xlog_info("proxy server [%s:%d].",
        inet_ntoa(xserver_addr.sin_addr), ntohs(xserver_addr.sin_port));
    xlog_info("tunnel server listen at [%s:%d]...",
        inet_ntoa(taddr.sin_addr), ntohs(taddr.sin_port));
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&conn_reqs);
    xlist_destroy(&io_buffers);
    xlist_destroy(&tserver_ctxs);
end:
    xlog_info("end of loop.");
    uv_close((uv_handle_t*) &io_tserver, NULL);
    xlog_exit();

    return 0;
}