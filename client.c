/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>

#include "common.h"
#include "xlog.h"
#include "xlist.h"
#include "crypto.h"

#define RECONNECT_INTERVAL  (10 * 1000) /* ms */
#define KEEPIDLE_TIME       (40) /* s */

enum {
    STAGE_INIT,    /* server connecting */
    STAGE_COMMAND, /* server connected */
    STAGE_CONNECT, /* remote connecting */
    STAGE_FORWARD, /* remote connected */
};

/*  --------         --------         --------
 * | remote | <---> | client | <---> | server |
 *  --------         --------         --------
 */

typedef struct {
    uv_write_t wreq;
    u32_t idx;
    u32_t len;
    char buffer[MAX_SOCKBUF_SIZE - sizeof(uv_write_t) - 8];
} io_buf_t;

typedef struct {
    uv_tcp_t io_server;
    uv_tcp_t io_remote;
    io_buf_t* pending_iob;  /* the pending 'io_buf_t' before 'io_remote' connected */
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t ref_count;         /* increase when 'io_server' or 'io_remote' opened, decrease when closed */
    u8_t server_blocked;    /* server reading is stopped */
    u8_t remote_blocked;    /* remote reading is stopped */
    u8_t stage;
} client_ctx_t;

static uv_loop_t* loop;
static uv_timer_t reconnect_timer;

static struct sockaddr_in server_addr;
static xlist_t client_ctxs; /* client_ctx_t */
static xlist_t io_buffers;  /* io_buf_t */
static xlist_t conn_reqs;   /* uv_connect_t */

static crypto_t crypto;     /* crypto between client and server */
static crypto_t cryptox;    /* crypto between client and proxy-client */
static u8_t crypto_key[16]; /* crypto key between client and server */
static u8_t cryptox_key[16];/* crypto key between client and proxy-client */
static u8_t device_id[DEVICE_ID_SIZE];

static void on_remote_write(uv_write_t* req, int status);
static void on_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_remote_connected(uv_connect_t* req, int status);
static int connect_remote(client_ctx_t* ctx, u8_t* addr, u16_t port);

static void on_server_write(uv_write_t* req, int status);
static void on_server_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_server_connected(uv_connect_t* req, int status);
static void new_server_connection(uv_timer_t* handle);

static void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);

    buf->base = iob->buffer;
    buf->len = sizeof(iob->buffer);
}

static void on_io_closed(uv_handle_t* handle)
{
    client_ctx_t* ctx = handle->data;

    if (ctx->ref_count > 1) {
        --ctx->ref_count;
    } else {

        if (ctx->pending_iob) {
            xlist_erase(&io_buffers, xlist_value_iter(ctx->pending_iob));
        }
        xlist_erase(&client_ctxs, xlist_value_iter(ctx));

        xlog_debug("current %zd ctxs, %zd iobufs.",
            xlist_size(&client_ctxs), xlist_size(&io_buffers));
    }
}

static void on_remote_write(uv_write_t* req, int status)
{
    client_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->server_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_remote) == 0) {
        xlog_debug("remote write queue cleared.");

        /* remote write queue cleared, start reading from server. */
        uv_read_start((uv_stream_t*) &ctx->io_server,
            on_iobuf_alloc, on_server_read);
        ctx->server_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    client_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from remote, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_server,
            &wbuf, 1, on_server_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_server) > MAX_WQUEUE_SIZE) {
            xlog_debug("server write queue pending.");

            /* stop reading from remote until server write queue cleared. */
            uv_read_stop(stream);
            ctx->remote_blocked = 1;
        }

        /* don't release 'iob' in this place,
         *'on_server_write' callback will do it.
         */
    } else if (nread < 0) {
        xlog_debug("disconnected from remote: %s.", uv_err_name(nread));

        uv_close((uv_handle_t*) stream, on_io_closed);
        uv_close((uv_handle_t*) &ctx->io_server, on_io_closed);

        if (buf->base) {
            /* 'buf->base' may be 'NULL' when 'nread' < 0. */
            xlist_erase(&io_buffers, xlist_value_iter(iob));
        }

    } else {
        xlist_erase(&io_buffers, xlist_value_iter(iob));
    }
}

static void on_remote_connected(uv_connect_t* req, int status)
{
    client_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_error("connect remote failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before remote connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->io_remote, on_io_closed);
            uv_close((uv_handle_t*) &ctx->io_server, on_io_closed);
        // }

    } else {
        xlog_debug("remote connected.");

        if (ctx->pending_iob) {
            /* write 'ctx->pending_iob' to remote. */
            io_buf_t* iob = ctx->pending_iob;
            uv_buf_t buf;

            buf.base = iob->buffer + iob->idx;
            buf.len = iob->len;

            iob->wreq.data = ctx;
            ctx->pending_iob = NULL;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_remote,
                &buf, 1, on_remote_write);
        }

        uv_read_start((uv_stream_t*) &ctx->io_remote,
            on_iobuf_alloc, on_remote_read);
        uv_read_start((uv_stream_t*) &ctx->io_server,
            on_iobuf_alloc, on_server_read);

        ctx->stage = STAGE_FORWARD;
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static int connect_remote(client_ctx_t* ctx, u8_t* addr, u16_t port)
{
    struct sockaddr_in remote_addr;
    uv_connect_t* req = xlist_alloc_back(&conn_reqs);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = port;

    memcpy(&remote_addr.sin_addr, addr, 4);
    xlog_debug("connecting remote [%s:%d]...",
        inet_ntoa(remote_addr.sin_addr), ntohs(port));

    req->data = ctx;
    /* 'io_remote' will be opened, increase refcount. */
    ++ctx->ref_count;

    if (uv_tcp_connect(req, &ctx->io_remote,
            (struct sockaddr*) &remote_addr, on_remote_connected) != 0) {
        xlog_error("connect remote failed immediately.");

        uv_close((uv_handle_t*) &ctx->io_remote, on_io_closed);
        xlist_erase(&conn_reqs, xlist_value_iter(req));
        return -1;
    }

    ctx->stage = STAGE_CONNECT;
    return 0;
}

static void on_server_write(uv_write_t* req, int status)
{
    client_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->remote_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_server) == 0) {
        xlog_debug("server write queue cleared.");

        /* server write queue cleared, start reading from remote. */
        uv_read_start((uv_stream_t*) &ctx->io_server,
            on_iobuf_alloc, on_remote_read);
        ctx->remote_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_server_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    client_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        if (ctx->stage == STAGE_FORWARD) {
            uv_buf_t wbuf;

            xlog_debug("recved %zd bytes from server, forward.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx;

            cryptox.decrypt(&ctx->dctx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_remote,
                &wbuf, 1, on_remote_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_remote) > MAX_WQUEUE_SIZE) {
                xlog_debug("remote write queue pending.");

                /* stop reading from server until remote write queue cleared. */
                uv_read_stop(stream);
                ctx->server_blocked = 1;
            }

            /* don't release 'iob' in this place,
             * 'on_remote_write' callback will do it.
             */
            return;
        }

        if (ctx->stage == STAGE_COMMAND) {
            /* start a new server connection always. */
            new_server_connection(NULL);

            if (nread >= sizeof(cmd_t) + MAX_NONCE_LEN) {
                cmd_t* cmd = (cmd_t*) (buf->base + MAX_NONCE_LEN);

                cryptox.init(&ctx->dctx, cryptox_key, (u8_t*) buf->base);
                cryptox.decrypt(&ctx->dctx, (u8_t*) cmd, nread - MAX_NONCE_LEN);

                convert_nonce((u8_t*) buf->base);
                cryptox.init(&ctx->ectx, cryptox_key, (u8_t*) buf->base);

                if (!is_valid_cmd(cmd)) {
                    xlog_warn("got an error packet (content) from proxy client.");
                    uv_close((uv_handle_t*) stream, on_io_closed);

                } else if (cmd->cmd == CMD_CONNECT_IPV4) {
                    xlog_debug("got CONNECT_IPV4 cmd (%s:%d) from proxy client, process.",
                        inet_ntoa(*(struct in_addr*) cmd->i.addr), ntohs(cmd->i.port));

                    /* stop reading from server until remote connected.
                     * so we can't know this connection is closed (by server) or not
                     * before remote connected, TODO.
                     */
                    uv_read_stop(stream);

                    if (connect_remote(ctx, cmd->i.addr, cmd->i.port) != 0) {
                        /* connect failed immediately, just close this connection. */
                        uv_close((uv_handle_t*) stream, on_io_closed);
                    }

                    if (nread > sizeof(cmd_t) + MAX_NONCE_LEN) {
                        xlog_debug("pending the remaining iob.");

                        iob->idx = sizeof(cmd_t) + MAX_NONCE_LEN;
                        iob->len = nread - sizeof(cmd_t) - MAX_NONCE_LEN;
                        /* 'iob' free later. */
                        ctx->pending_iob = iob;
                        return;
                    }

                } else {
                    xlog_warn("got an error command from proxy client.");
                    uv_close((uv_handle_t*) stream, on_io_closed);
                }

            } else {
                xlog_warn("got an error packet (length) from server.");
                uv_close((uv_handle_t*) stream, on_io_closed);
            }

        } else {
            /* should not reach here */
            xlog_error("unexpected state happen when read.");
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from server: %s, stage %d.",
            uv_err_name(nread), ctx->stage);

        if (ctx->stage == STAGE_FORWARD) {
            uv_close((uv_handle_t*) &ctx->io_remote, on_io_closed);
        } else if (ctx->stage == STAGE_COMMAND) {
            /* delay connect */
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_INTERVAL, RECONNECT_INTERVAL);
        } else { /* STAGE_CONNECT */
            /* should not reach here */
            xlog_error("unexpected state happen when disconnect.");
        }

        uv_close((uv_handle_t*) stream, on_io_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0.
         * just 'return' in this situation.
         */
        if (!buf->base) return;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void report_device_id(client_ctx_t* ctx)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);
    cmd_t* cmd = (cmd_t*) (iob->buffer + MAX_NONCE_LEN);
    uv_buf_t buf;

    iob->wreq.data = ctx;

    buf.base = iob->buffer;
    buf.len = sizeof(cmd_t) + MAX_NONCE_LEN;

    /* generate and prepend iv in the first packet */
    rand_bytes((u8_t*) iob->buffer, MAX_NONCE_LEN);

    cmd->tag = CMD_TAG;
    cmd->major = VERSION_MAJOR;
    cmd->minor = VERSION_MINOR;
    cmd->cmd = CMD_REPORT_DEVID;

    memcpy(cmd->d.devid, device_id, DEVICE_ID_SIZE);

    crypto.init(&ctx->ectx, crypto_key, (u8_t*) iob->buffer);
    crypto.encrypt(&ctx->ectx, (u8_t*) cmd, sizeof(cmd_t));

    uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_server,
        &buf, 1, on_server_write);
}

static void on_server_connected(uv_connect_t* req, int status)
{
    client_ctx_t* ctx = req->data;

    if (status < 0) {
        uv_close((uv_handle_t*) &ctx->io_server, on_io_closed);

        xlog_error("connect server failed: %s, retry after %d seconds.",
            uv_err_name(status), RECONNECT_INTERVAL / 1000);

        if (!reconnect_timer.data) {
            xlog_debug("start reconnect timer.");
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_INTERVAL, RECONNECT_INTERVAL);
        }

    } else {
        xlog_info("server connected.");

        uv_timer_stop(&reconnect_timer);
        uv_read_start((uv_stream_t*) &ctx->io_server,
            on_iobuf_alloc, on_server_read);
        /* enable tcp-keepalive. */
        uv_tcp_keepalive(&ctx->io_server, 1, KEEPIDLE_TIME);

        report_device_id(ctx);

        ctx->stage = STAGE_COMMAND;
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static void new_server_connection(uv_timer_t* timer)
{
    client_ctx_t* ctx = xlist_alloc_back(&client_ctxs);
    uv_connect_t* req = xlist_alloc_back(&conn_reqs);

    uv_tcp_init(loop, &ctx->io_server);
    uv_tcp_init(loop, &ctx->io_remote);

    ctx->io_server.data = ctx;
    ctx->io_remote.data = ctx;
    ctx->pending_iob = NULL;
    ctx->ref_count = 1;
    ctx->server_blocked = 0;
    ctx->remote_blocked = 0;
    ctx->stage = STAGE_INIT;

    req->data = ctx;

    reconnect_timer.data = timer; /* mark timer is started or not */

    xlog_debug("connecting server [%s:%d]...",
        inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    if (uv_tcp_connect(req, &ctx->io_server,
            (struct sockaddr*) &server_addr, on_server_connected) != 0) {
        xlog_error("connect server failed immediately.");

        uv_close((uv_handle_t*) &ctx->io_server, on_io_closed);
        xlist_erase(&conn_reqs, xlist_value_iter(req));
    }
}

int main(int argc, char** argv)
{
    const char* server_str = "127.0.0.1";
    const char* devid_str = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int verbose = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-s")) {
            if (++i < argc) server_str = argv[i];
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
        } else if (!strcmp(argv[i], "-v")) {
            verbose = 1;
        } else {
            // usage, TODO
            fprintf(stderr, "wrong args.\n");
            return 1;
        }
    }

    loop = uv_default_loop();

    seed_rand((u32_t) time(NULL));

    xlog_init(NULL);
    xlog_ctrl(verbose ? XLOG_DEBUG : XLOG_INFO, 0, 0);

    if (!devid_str) {
        xlog_info("device id not set, use default.");
        memcpy(device_id, "\x11\x22\x33\x44\x55\x66\x77\x88", DEVICE_ID_SIZE);
        // TODO, get MAC?
    } else if (str_to_devid(device_id, devid_str) != 0) {
        xlog_error("invalid device id string [%s].", devid_str);
        goto end;
    }

    if (passwd) {
        derive_key(crypto_key, passwd);
    } else {
        xlog_info("password not set, disable crypto with server.");
        method = CRYPTO_NONE;
    }
    if (passwdx) {
        derive_key(cryptox_key, passwdx);
    } else {
        xlog_info("PASSWORD (-K) not set, disable crypto with proxy client.");
        methodx = CRYPTO_NONE;
    }

    if (crypto_init(&crypto, method) != 0) {
        xlog_error("invalid crypto method: %d.", method);
        goto end;
    }
    if (crypto_init(&cryptox, methodx) != 0) {
        xlog_error("invalid crypto METHOD: %d.", methodx);
        goto end;
    }

    if (parse_ip4_str(server_str, DEF_SERVER_PORT, &server_addr) != 0) {
        xlog_error("invalid server address [%s].", server_str);
        goto end;
    }

    xlist_init(&client_ctxs, sizeof(client_ctx_t), NULL);
    xlist_init(&io_buffers, sizeof(io_buf_t), NULL);
    xlist_init(&conn_reqs, sizeof(uv_connect_t), NULL);

    uv_timer_init(loop, &reconnect_timer);

    new_server_connection(NULL);
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&conn_reqs);
    xlist_destroy(&io_buffers);
    xlist_destroy(&client_ctxs);
end:
    xlog_info("end of loop.");
    xlog_exit();

    return 0;
}