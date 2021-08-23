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
#include <sys/resource.h> /* for setrlimit() */
#endif
#ifdef __linux__
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#endif

#include "common.h"
#include "xlog.h"
#include "xlist.h"
#include "crypto.h"

#define KEEPIDLE_TIME       (40) /* s */

/*  --------------         --------------         --------------
 * | proxy-server | <---> | proxy-client | <---> | applications |
 *  --------------         --------------         --------------
 *                         (tunnel-server)        (tunnel-client)
 */

typedef struct {
    uv_write_t wreq;
    u32_t idx;
    u32_t len;
    char buffer[0];
} io_buf_t;

typedef struct {
    uv_tcp_t io_tclient;    /* tunnel-client */
    uv_tcp_t io_xserver;    /* proxy-server */
    io_buf_t* pending_iob;
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t ref_count;         /* increase when 'io_xserver' or 'io_tclient' opened, decrease when closed */
    u8_t tclient_blocked;
    u8_t xserver_blocked;
} tserver_ctx_t;

static uv_loop_t* loop;

static union { struct sockaddr x; struct sockaddr_in6 d; } xserver_addr;
static union { cmd_t m; u8_t _[CMD_MAX_SIZE]; } tunnel_maddr;

static xlist_t tserver_ctxs;/* tserver_ctx_t */
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
    buf->len = MAX_SOCKBUF_SIZE;
}

static void on_io_closed(uv_handle_t* handle)
{
    tserver_ctx_t* ctx = handle->data;

    if (ctx->ref_count > 1) {
        --ctx->ref_count;
    } else {
        if (ctx->pending_iob) {
            xlist_erase(&io_buffers, xlist_value_iter(ctx->pending_iob));
        }
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
        xlog_debug("disconnected from proxy server: %s.",
            uv_err_name((int) nread));

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
        xlog_debug("disconnected from tunnel client: %s.", uv_err_name((int) nread));

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

static void init_connect_cmd(tserver_ctx_t* ctx,
                u8_t code, u16_t port, u8_t* addr, u32_t addrlen)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);
    u8_t* pbuf = (u8_t*) iob->buffer;
    cmd_t* cmd;
    u8_t dnonce[16];

    if (is_valid_devid(device_id)) {
        /* generate and prepend iv in the first packet */
        rand_bytes(pbuf, MAX_NONCE_LEN);

        cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

        cmd->tag = CMD_TAG;
        cmd->major = VERSION_MAJOR;
        cmd->minor = VERSION_MINOR;
        cmd->cmd = CMD_CONNECT_CLIENT;
        cmd->len = DEVICE_ID_SIZE;

        memcpy(cmd->data, device_id, DEVICE_ID_SIZE);

        crypto.init(&ctx->ectx, crypto_key, pbuf);
        crypto.encrypt(&ctx->ectx, (u8_t*) cmd, CMD_MAX_SIZE);

        pbuf += MAX_NONCE_LEN + CMD_MAX_SIZE;
    }

    /* generate and prepend iv in the first packet */
    rand_bytes(pbuf, MAX_NONCE_LEN);

    cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

    cmd->tag = CMD_TAG;
    cmd->major = VERSION_MAJOR;
    cmd->minor = VERSION_MINOR;
    cmd->cmd = code;
    cmd->len = (u8_t) addrlen;
    cmd->port = port;

    memcpy(cmd->data, addr, addrlen);

    memcpy(dnonce, pbuf, MAX_NONCE_LEN);
    convert_nonce(dnonce);

    cryptox.init(&ctx->ectx, cryptox_key, pbuf);
    cryptox.init(&ctx->dctx, cryptox_key, dnonce);
    cryptox.encrypt(&ctx->ectx, (u8_t*) cmd, CMD_MAX_SIZE);

    iob->wreq.data = ctx;
    iob->len = pbuf + MAX_NONCE_LEN + CMD_MAX_SIZE - (u8_t*) iob->buffer;

    ctx->pending_iob = iob;
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
        uv_buf_t wbuf;

        xlog_debug("proxy server connected.");

        uv_read_start((uv_stream_t*) &ctx->io_tclient,
            on_iobuf_alloc, on_tclient_read);
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
        /* enable tcp-keepalive. */
        uv_tcp_keepalive(&ctx->io_xserver, 1, KEEPIDLE_TIME);

        /* send connect command. */
        wbuf.base = ctx->pending_iob->buffer;
        wbuf.len = ctx->pending_iob->len;

        uv_write(&ctx->pending_iob->wreq, (uv_stream_t*) &ctx->io_xserver,
            &wbuf, 1, on_xserver_write);

        ctx->pending_iob = NULL;
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static int connect_xserver(tserver_ctx_t* ctx)
{
    uv_connect_t* req = xlist_alloc_back(&conn_reqs);

    xlog_debug("connecting porxy server [%s]...", addr_to_str(&xserver_addr));

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
        if (tunnel_maddr.m.len) {
#endif
            init_connect_cmd(ctx, tunnel_maddr.m.cmd,
                tunnel_maddr.m.port, tunnel_maddr.m.data, tunnel_maddr.m.len);
#ifdef __linux__
        } else {
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif
            union {
                struct sockaddr     vx;
                struct sockaddr_in  v4;
                struct sockaddr_in6 v6;
            } dest;
            socklen_t len = sizeof(dest);

            if (getsockopt(ctx->io_tclient.io_watcher.fd,
                    SOL_IP, SO_ORIGINAL_DST, &dest, &len) == 0) {
                init_connect_cmd(ctx, CMD_CONNECT_IPV4,
                    dest.v4.sin_port, (u8_t*) &dest.v4.sin_addr, 4);

            } else if (getsockopt(ctx->io_tclient.io_watcher.fd,
                    SOL_IPV6, IP6T_SO_ORIGINAL_DST, &dest, &len) == 0) {
                init_connect_cmd(ctx, CMD_CONNECT_IPV6,
                    dest.v6.sin6_port, (u8_t*) &dest.v6.sin6_addr, 16);

            } else {
                xlog_warn("getsockopt IP6T_SO_ORIGINAL_DST failed: %s.", strerror(errno));
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

static int init_tunnel_maddr(const char* addrstr)
{
    union {
        struct sockaddr     dx;
        struct sockaddr_in  d4;
        struct sockaddr_in6 d6;
        struct sockaddr_dm  dm;
    } _;

    if (parse_ip_str(addrstr, -1, &_.dx) == 0) {

        if (_.dx.sa_family == AF_INET) {
            tunnel_maddr.m.cmd = CMD_CONNECT_IPV4;
            tunnel_maddr.m.len = 4;
            tunnel_maddr.m.port = _.d4.sin_port;

            memcpy(tunnel_maddr.m.data, &_.d4.sin_addr, 4);

        } else {
            tunnel_maddr.m.cmd = CMD_CONNECT_IPV6;
            tunnel_maddr.m.len = 16;
            tunnel_maddr.m.port = _.d6.sin6_port;

            memcpy(tunnel_maddr.m.data, &_.d6.sin6_addr, 16);
        }

    } else if (parse_domain_str(addrstr, -1, &_.dm) == 0) {

        tunnel_maddr.m.cmd = CMD_CONNECT_DOMAIN;
        tunnel_maddr.m.len = (u8_t) (strlen(_.dm.sdm_addr) + 1);
        tunnel_maddr.m.port = _.dm.sdm_port;

        memcpy((char*) tunnel_maddr.m.data, _.dm.sdm_addr,
            tunnel_maddr.m.len);

    } else {
        return -1;
    }

    return 0;
}

static void usage(const char* s)
{
    fprintf(stderr, "trp v%d.%d.%d, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -x <address>  proxy server connect to. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -b <address>  tunnel server listen at. (default: 127.0.0.1:%d)\n", DEF_TSERVER_PORT);
#ifdef __linux__
    fprintf(stderr, "  -t <address>  target tunnel to. (default: transparent proxy mode)\n");
#else
    fprintf(stderr, "  -t <address>  target tunnel to.\n");
#endif
    fprintf(stderr, "  -d <devid>    device id of client connect to. (default: not connect client)\n");
    fprintf(stderr, "  -m <method>   crypto method with proxy server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   crypto method with client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -k <password> crypto password with proxy server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> crypto password with client. (default: none)\n");
#ifdef _WIN32
    fprintf(stderr, "  -L <path>     write output to file. (default: write to STDOUT)\n");
#else
    fprintf(stderr, "  -n <number>   set max number of open files.\n");
    fprintf(stderr, "  -L <path>     write output to file and run as daemon. (default: write to STDOUT)\n");
#endif
    fprintf(stderr, "  -v            output verbosely.\n");
    fprintf(stderr, "  -h            print this help message.\n");
    fprintf(stderr, "[address]:\n");
    fprintf(stderr, "  1.2.3.4:8080  IPV4 string with port.\n");
    fprintf(stderr, "  1.2.3.4       IPV4 string with default port.\n");
    fprintf(stderr, "  :8080         IPV4 string with default address.\n");
    fprintf(stderr, "  [::1]:8080    IPV6 string with port.\n");
    fprintf(stderr, "  [::1]         IPV6 string with default port.\n");
    fprintf(stderr, "  []:8080       IPV6 string with default address.\n");
    fprintf(stderr, "  []            IPV6 string with default address and port.\n");
    fprintf(stderr, "  abc.com:8080  DOMAIN string with port.\n");
    fprintf(stderr, "  abc.com       DOMAIN string with default port.\n");
    fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
    uv_tcp_t io_tserver; /* tunnel server listen io */
    union { struct sockaddr x; struct sockaddr_in6 d; } taddr;
    const char* xserver_str = "127.0.0.1";
    const char* tserver_str = "127.0.0.1";
    const char* tunnel_str = NULL;
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
#ifndef _WIN32
    int nofile = 0;
#endif
    int verbose = 0;
    int error, i;

    for (i = 1; i < argc; ++i) {
        char opt;
        char* arg;

        if (argv[i][0] != '-' || argv[i][1] == '\0') {
            fprintf(stderr, "wrong args [%s].\n", argv[i]);
            usage(argv[0]);
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
        case 'x': xserver_str = arg; continue;
        case 'b': tserver_str = arg; continue;
        case 't':  tunnel_str = arg; continue;
        case 'd':   devid_str = arg; continue;
        case 'm':      method = atoi(arg); continue;
        case 'M':     methodx = atoi(arg); continue;
        case 'k':      passwd = arg; continue;
        case 'K':     passwdx = arg; continue;
#ifndef _WIN32
        case 'n':      nofile = atoi(arg); continue;
#endif
        case 'L':     logfile = arg; continue;
        }

        fprintf(stderr, "invalid option [-%c].\n", opt);
        usage(argv[0]);
        return 1;
    }

#ifndef _WIN32
    if (logfile && daemon(1, 0) != 0) {
        xlog_error("run as daemon failed: %s.", strerror(errno));
    }

    signal(SIGPIPE, SIG_IGN);

    if (nofile > 1024) {
        struct rlimit limit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            xlog_warn("set NOFILE limit to %d failed: %s.",
                nofile, strerror(errno));
        } else {
            xlog_info("set NOFILE limit to %d.", nofile);
        }
    }
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

    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xserver_addr.x) != 0) {
        struct sockaddr_dm dm;

        if (parse_domain_str(xserver_str, DEF_XSERVER_PORT, &dm) != 0
                || resolve_domain_sync(loop, &dm, &xserver_addr.x) != 0) {
            xlog_error("invalid proxy server address [%s].", xserver_str);
            goto end;
        }
    }

    if (parse_ip_str(tserver_str, DEF_TSERVER_PORT, &taddr.x) != 0) {
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
    } else if (init_tunnel_maddr(tunnel_str) != 0) {
        xlog_error("invalid tunnel address [%s].", tunnel_str);
        goto end;
    } else {
        xlog_info("tunnel to [%s].", maddr_to_str(&tunnel_maddr.m));
    }

    uv_tcp_init(loop, &io_tserver);
    uv_tcp_bind(&io_tserver, &taddr.x, 0);

    error = uv_listen((uv_stream_t*) &io_tserver,
                LISTEN_BACKLOG, on_tclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.",
            addr_to_str(&taddr), uv_strerror(error));
        goto end;
    }

    xlist_init(&tserver_ctxs, sizeof(tserver_ctx_t), NULL);
    xlist_init(&io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);
    xlist_init(&conn_reqs, sizeof(uv_connect_t), NULL);

    xlog_info("proxy server [%s].", addr_to_str(&xserver_addr));
    xlog_info("tunnel server listen at [%s]...", addr_to_str(&taddr));
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&conn_reqs);
    xlist_destroy(&io_buffers);
    xlist_destroy(&tserver_ctxs);
end:
    xlog_info("end of loop.");
    xlog_exit();

    return 0;
}