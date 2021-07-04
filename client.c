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

#include "common.h"
#include "xlog.h"
#include "xlist.h"
#include "crypto.h"

#define RECONNECT_INTERVAL  (10 * 1000) /* ms */
#define KEEPIDLE_TIME       (40) /* s */
#define DEFAULT_DEVID       "\x11\x22\x33\x44\x55\x66\x77\x88"

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
            uv_buf_t wbuf;

            wbuf.base = iob->buffer + iob->idx;
            wbuf.len = iob->len;

            iob->wreq.data = ctx;
            ctx->pending_iob = NULL;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_remote,
                &wbuf, 1, on_remote_write);
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
    xlog_debug("connecting remote [%s]...", addr_to_str(&remote_addr));

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
        uv_read_start((uv_stream_t*) &ctx->io_remote,
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
                    xlog_debug("got CONNECT_IPV4 cmd (%s) from proxy client, process.",
                        maddr_to_str(cmd));

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
            if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
                uv_timer_start(&reconnect_timer, new_server_connection,
                    RECONNECT_INTERVAL, 0);
            }
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
    uv_buf_t wbuf;

    iob->wreq.data = ctx;

    wbuf.base = iob->buffer;
    wbuf.len = sizeof(cmd_t) + MAX_NONCE_LEN;

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
        &wbuf, 1, on_server_write);
}

static void on_server_connected(uv_connect_t* req, int status)
{
    static int retry_displayed;

    client_ctx_t* ctx = req->data;

    if (status < 0) {
        uv_close((uv_handle_t*) &ctx->io_server, on_io_closed);

        if (!retry_displayed) {
            xlog_error("connect server failed: %s, retry every %d seconds.",
                uv_err_name(status), RECONNECT_INTERVAL / 1000);
            retry_displayed = 1;
        }

        /* reconnect after RECONNECT_INTERVAL/1000 second. */
        if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_INTERVAL, 0);
        }

    } else {

        if (!retry_displayed) {
            xlog_debug("server connected.");
        } else {
            xlog_info("server connected.");
            retry_displayed = 0;
        }

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

    xlog_debug("connecting server [%s]...", addr_to_str(&server_addr));

    if (uv_tcp_connect(req, &ctx->io_server,
            (struct sockaddr*) &server_addr, on_server_connected) != 0) {
        xlog_error("connect server failed immediately.");

        uv_close((uv_handle_t*) &ctx->io_server, on_io_closed);
        xlist_erase(&conn_reqs, xlist_value_iter(req));

        /* reconnect after RECONNECT_INTERVAL/1000 second.
         * 'reconnect_timer' is inactive when 'new_server_connection'
         * is invoked by 'reconnect_timer'. so,
         * 'uv_timer_start' will not be called twice anyway.
         */
        if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_INTERVAL, 0);
        }
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp v%d.%d, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, s);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -s <ip:port>  "
        "server connect to. (default: 127.0.0.1:%d)\n", DEF_SERVER_PORT);
    fprintf(stderr, "  -d <devid>    "
        "device id of this client. (default: %s)\n", devid_to_str((u8_t*) DEFAULT_DEVID));
    fprintf(stderr, "  -m <method>   "
        "crypto method with server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   "
        "crypto method with proxy client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -k <password> "
        "crypto password with server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> "
        "crypto password with proxy client. (default: none)\n");
#ifdef _WIN32
    fprintf(stderr, "  -L <path>     "
        "write output to file. (default: write to STDOUT)\n");
#else
    fprintf(stderr, "  -L <path>     "
        "write output to file and run as daemon. (default: write to STDOUT)\n");
#endif
    fprintf(stderr, "  -v            output verbosely.\n");
    fprintf(stderr, "  -h            print this help message.\n");
    fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
    const char* server_str = "127.0.0.1";
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int verbose = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        char opt;
        char* arg;

        if (argv[i][0] != '-' || argv[i][1] == '\0') {
            fprintf(stderr, "wrong args [%s].\n", argv[i]);
            return 1;
        }

        opt = argv[i][1];

        switch (opt) {
        case 'v': verbose = 1; continue;
        case 'h':
            usage(argv[0]);
            return 1;
        }

        arg = argv[i][2] ? argv[i] + 2 : (++i < argc ? argv[i] : NULL);

        if (arg) switch (opt) {
        case 's': server_str = arg; continue;
        case 'd':  devid_str = arg; continue;
        case 'm':     method = atoi(arg); continue;
        case 'M':    methodx = atoi(arg); continue;
        case 'k':     passwd = arg; continue;
        case 'K':    passwdx = arg; continue;
        case 'L':    logfile = arg; continue;
        }

        fprintf(stderr, "invalid option [-%c].\n", opt);
        return 1;
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
    if (!verbose) {
        xlog_ctrl(XLOG_INFO, 0, 0);
    } else {
        xlog_info("enable verbose output.");
    }

    if (!devid_str) {
        xlog_info("device id not set, use default.");
        memcpy(device_id, DEFAULT_DEVID, DEVICE_ID_SIZE);
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