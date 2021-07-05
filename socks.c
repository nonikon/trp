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

#define KEEPIDLE_TIME       (40) /* s */

enum {
    STAGE_MESSAGE, /* waiting for socks5-client select message or socks4-client command */
    STAGE_COMMAND, /* waiting for socks5-client command */
    STAGE_CONNECT, /* remote connecting */
    STAGE_FORWARD, /* remote connected */
};

/*  --------------         --------------         --------------
 * | proxy-server | <---> | proxy-client | <---> | applications |
 *  --------------         --------------         --------------
 *                         (socks-server)         (socks_client)
 *
 * SOCKS5 Protocol: https://www.ietf.org/rfc/rfc1928.txt
 */

typedef struct {
    uv_tcp_t io_sclient;    /* SOCKS-client */
    uv_tcp_t io_xserver;    /* proxy-server */
    cmd_t dest_addr;
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t ref_count;         /* increase when 'io_xserver' or 'io_sclient' opened, decrease when closed */
    u8_t sclient_blocked;
    u8_t xserver_blocked;
    u8_t stage;
} sserver_ctx_t;

typedef struct {
    uv_write_t wreq;
    char buffer[MAX_SOCKBUF_SIZE - sizeof(uv_write_t)];
} io_buf_t;

static uv_loop_t* loop;

static struct sockaddr_in xserver_addr;
static xlist_t sserver_ctxs;/* sserver_ctx_t */
static xlist_t io_buffers;  /* io_buf_t */
static xlist_t conn_reqs;   /* uv_connect_t */

static crypto_t crypto;
static crypto_t cryptox;
static u8_t crypto_key[16];
static u8_t cryptox_key[16];
static u8_t device_id[DEVICE_ID_SIZE];

static void on_xserver_write(uv_write_t* req, int status);
static void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_sclient_write(uv_write_t* req, int status);
static void on_sclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

static void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);

    buf->base = iob->buffer;
    buf->len = sizeof(iob->buffer);
}

static void on_io_closed(uv_handle_t* handle)
{
    sserver_ctx_t* ctx = handle->data;

    if (ctx->ref_count > 1) {
        --ctx->ref_count;
    } else {
        xlist_erase(&sserver_ctxs, xlist_value_iter(ctx));

        xlog_debug("current %zd ctxs, %zd iobufs.",
            xlist_size(&sserver_ctxs), xlist_size(&io_buffers));
    }
}

static void on_xserver_write(uv_write_t* req, int status)
{
    sserver_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->sclient_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_xserver) == 0) {
        xlog_debug("proxy server write queue cleared.");

        /* proxy server write queue cleared, start reading from SOCKS client. */
        uv_read_start((uv_stream_t*) &ctx->io_sclient,
            on_iobuf_alloc, on_sclient_read);
        ctx->sclient_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    sserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from proxy server, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        cryptox.decrypt(&ctx->dctx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_sclient,
            &wbuf, 1, on_sclient_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_sclient) > MAX_WQUEUE_SIZE) {
            xlog_debug("SOCKS client write queue pending.");

            /* stop reading from proxy server until SOCKS client write queue cleared. */
            uv_read_stop(stream);
            ctx->xserver_blocked = 1;
        }

        /* don't release 'iob' in this place,
         *'on_sclient_write' callback will do it.
         */
    } else if (nread < 0) {
        xlog_debug("disconnected from proxy server: %s.",
            uv_err_name((int) nread));

        uv_close((uv_handle_t*) stream, on_io_closed);
        uv_close((uv_handle_t*) &ctx->io_sclient, on_io_closed);

        if (buf->base) {
            /* 'buf->base' may be 'NULL' when 'nread' < 0. */
            xlist_erase(&io_buffers, xlist_value_iter(iob));
        }

    } else {
        xlist_erase(&io_buffers, xlist_value_iter(iob));
    }
}

static void send_connect_cmd(sserver_ctx_t* ctx)
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

    memcpy(cmd, &ctx->dest_addr, sizeof(cmd_t));

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
    sserver_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_error("connect proxy server failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before proxy server connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->io_sclient, on_io_closed);
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        // }

    } else {
        xlog_debug("proxy server connected.");

        uv_read_start((uv_stream_t*) &ctx->io_sclient,
            on_iobuf_alloc, on_sclient_read);
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
        /* enable tcp-keepalive. */
        uv_tcp_keepalive(&ctx->io_xserver, 1, KEEPIDLE_TIME);

        send_connect_cmd(ctx);

        ctx->stage = STAGE_FORWARD;
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static int connect_xserver(sserver_ctx_t* ctx)
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

    ctx->stage = STAGE_CONNECT;
    return 0;
}

static void on_sclient_write(uv_write_t* req, int status)
{
    sserver_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xserver_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_sclient) == 0) {
        xlog_debug("SOCKS client write queue cleared.");

        /* SOCKS client write queue cleared, start reading from proxy server. */
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
        ctx->xserver_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

/* SOCKS4/SOCKS5 handshake */
static int socks_handshake(sserver_ctx_t* ctx, uv_buf_t* buf)
{
    if (ctx->stage == STAGE_MESSAGE) {

        /* 'VER' == 0x05 (SOCKS5) */
        if (buf->base[0] == 0x05) {
            /* SOCKS5 client request:
             * +-----+----------+----------+
             * | VER | NMETHODS | METHODS  |
             * +-----+----------+----------+
             * |  1  |    1     | 1 to 255 |
             * +-----+----------+----------+
             * SOCKS5 server response:
             * +-----+--------+
             * | VER | METHOD |
             * +-----+--------+
             * |  1  |   1    |
             * +-----+--------+
             * METHOD:
             *   X'00' NO AUTHENTICATION REQUIRED
             *   X'01' GSSAPI
             *   X'02' USERNAME/PASSWORD
             *   X'03' to X'7F' IANA ASSIGNED
             *   X'80' to X'FE' RESERVED FOR PRIVATE METHODS
             *   X'FF' NO ACCEPTABLE METHODS
             */

            if (buf->len < 3 || buf->base[1] == 0) { /* 'NMETHODS' == 0 */
                xlog_warn("invalid socks5 select message from client.");
                return -1;
            }

            xlog_debug("socks5 select message from client: %d bytes, %d methods.",
                buf->len, buf->base[1]);

            buf->base[1] = 0x00; /* select 'METHOD' 0x00 */
            buf->len = 2;

            ctx->stage = STAGE_COMMAND;
            return 0;
        }

        /* 'VER' == 0x04 (SOCKS4) */
        if (buf->base[0] == 0x04) {
            /* SOCKS4 client request:
             * +----+----+---------+-------+----------+------+
             * | VN | CD | DSTPORT | DSTIP |  USERID  | NULL |
             * +----+----+---------+-------+----------+------+
             * | 1  | 1  |    2    |   4   | Variable |   1  |
             * +----+----+---------+-------+----------+------+
             *  SOCKS4 server response:
             * +----+----+---------+-------+
             * | VN | CD | DSTPORT | DSTIP |
             * +----+----+---------+-------+
             * | 1  | 1  |    2    |   4   |
             * +----+----+---------+-------+
             */

            if (buf->len < 9 || buf->base[1] != 0x01) {/* 'CD' != 0x01 (CONNECT) */
                xlog_warn("invalid socks4 command from client.");
                return -1;
            }

            ctx->dest_addr.tag = CMD_TAG;
            ctx->dest_addr.major = VERSION_MAJOR;
            ctx->dest_addr.minor = VERSION_MINOR;
            ctx->dest_addr.cmd = CMD_CONNECT_IPV4;

            memcpy(&ctx->dest_addr.i.port, buf->base + 2, 2);
            memcpy(&ctx->dest_addr.i.addr, buf->base + 4, 4);

            xlog_debug("got socks4 connect cmd, to [%s].", maddr_to_str(&ctx->dest_addr));

            buf->base[0] = 0x00; /* set 'VN' to 0x00 */
            buf->len = 8;

            if (connect_xserver(ctx) == 0) {
                /* assume that proxy server was connected successfully. */

                /* stop reading from socks client until proxy server connected. */
                uv_read_stop((uv_stream_t*) &ctx->io_sclient);

                buf->base[1] = 90; /* set 'CD' to 90 */
                return 0;
            }

            /* connect proxy server failed immediately. */
            buf->base[1] = 91; /* set 'CD' to 91 */
            return 1;
        }

        xlog_warn("invalid socks protocol version [%d].", buf->base[0]);
        return -1;
    }

    if (ctx->stage == STAGE_COMMAND) {
        /* SOCKS5 client request:
         * +-----+-----+-------+------+----------+----------+
         * | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
         * +-----+-----+-------+------+----------+----------+
         * |  1  |  1  | X'00' |  1   | Variable |    2     |
         * +-----+-----+-------+------+----------+----------+
         * SOCKS5 server response:
         * +-----+-----+-------+------+----------+----------+
         * | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
         * +-----+-----+-------+------+----------+----------+
         * |  1  |  1  | X'00' |  1   | Variable |    2     |
         * +-----+-----+-------+------+----------+----------+
         * CMD:
         *   X'01' CONNECT
         *   X'02' BIND
         *   X'03' UDP ASSOCIATE
         * ATYP:
         *   X'01' IP V4 address
         *   X'03' DOMAINNAME
         *   X'04' IP V6 address
         * REP:
         *   X'00' succeeded
         *   X'01' general SOCKS server failure
         *   X'02' connection not allowed by ruleset
         *   X'03' Network unreachable
         *   X'04' Host unreachable
         *   X'05' Connection refused
         *   X'06' TTL expired
         *   X'07' Command not supported
         *   X'08' Address type not supported
         *   X'09' to X'FF' unassigned
         */

        if (buf->len < 7
                || buf->base[0] != 0x05    /* 'VER' != 0x05 */
                || buf->base[2] != 0x00) { /* 'RSV' != 0x00 */
            xlog_warn("invalid socks5 request from client.");
            return -1;
        }

        if (buf->base[1] == 0x01) { /* 'CMD' == 0x01 (CONNECT) */

            if (buf->base[3] == 0x01) { /* 'ATYP' == 0x01 (IPV4) */

                if (buf->len == 6 + 4) {
                    ctx->dest_addr.tag = CMD_TAG;
                    ctx->dest_addr.major = VERSION_MAJOR;
                    ctx->dest_addr.minor = VERSION_MINOR;
                    ctx->dest_addr.cmd = CMD_CONNECT_IPV4;

                    memcpy(&ctx->dest_addr.i.addr, buf->base + 4, 4);
                    memcpy(&ctx->dest_addr.i.port, buf->base + 8, 2);

                    buf->base[1] = 0x00;
                } else {
                    xlog_warn("socks5 request packet len error.");
                    buf->base[1] = 0x01;
                }

            } else if (buf->base[3] == 0x03) { /* 'ATYP' == 0x03 (DOMAINNAME) */

                if ((u8_t) buf->base[4] < MAX_DOMAIN_LEN
                        && buf->len == 6 + 1 + (u8_t) buf->base[4]) {
                    ctx->dest_addr.tag = CMD_TAG;
                    ctx->dest_addr.major = VERSION_MAJOR;
                    ctx->dest_addr.minor = VERSION_MINOR;
                    ctx->dest_addr.cmd = CMD_CONNECT_DOMAIN;
                    ctx->dest_addr.m.domain[(u8_t) buf->base[4]] = 0;

                    memcpy(&ctx->dest_addr.m.domain, buf->base + 5, (u8_t) buf->base[4]);
                    memcpy(&ctx->dest_addr.m.port, buf->base + (u8_t) buf->base[4] + 5, 2);

                    buf->base[1] = 0x00;
                } else {
                    xlog_warn("socks5 request packet len error.");
                    buf->base[1] = 0x01;
                }

            } else {
                /* connect ipv6 not supported. */
                xlog_warn("unsupported socks5 address type %d.", buf->base[3]);
                buf->base[1] = 0x08;
            }

            if (buf->base[1] == 0x00) { /* no error */
                xlog_debug("got socks5 connect cmd, to [%s].", maddr_to_str(&ctx->dest_addr));

                if (connect_xserver(ctx) == 0) {
                    /* assume that proxy server was connected successfully. */
#if 0
                    struct sockaddr_in d;
                    int l = sizeof(d);

                    /* get local address. */
                    uv_tcp_getsockname(&ctx->io_xserver, (struct sockaddr*) &d, &l);
                    /* set BND.ADDR and BND.PORT */
                    memcpy(buf->base + 4, &d.sin_addr, 4);
                    memcpy(buf->base + 8, &d.sin_port, 2);

                    xlog_debug("local addr [%s].", addr_to_str(&d));
#else
                    memset(buf->base + 4, 0, 6);
#endif

                    /* stop reading from socks client until proxy server connected. */
                    uv_read_stop((uv_stream_t*) &ctx->io_sclient);

                    buf->base[3] = 1; /* set response 'ATYP' to IPV4 */
                    buf->len = 6 + 4;
                    return 0;
                }

                /* connect proxy server failed immediately. */
                buf->base[1] = 0x03;
            }

        } else {
            /* 'BIND' and 'UDP ASSOCIATE' not supported. */
            xlog_warn("unsupported socks5 command %d.", buf->base[1]);
            buf->base[1] = 0x07;
        }

        return 1;
    }

    /* can't reach here. */
    xlog_error("unexpected state happen.");
    return -1;
}

static void on_sclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    sserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        if (ctx->stage == STAGE_FORWARD) {

            xlog_debug("recved %zd bytes from SOCKS client, forward.", nread);

            cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
                &wbuf, 1, on_xserver_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_xserver) > MAX_WQUEUE_SIZE) {
                xlog_debug("proxy server write queue pending.");

                /* stop reading from SOCKS client until proxy server write queue cleared. */
                uv_read_stop(stream);
                ctx->sclient_blocked = 1;
            }

            /* 'iob' free later. */
            return;
        }

        switch (socks_handshake(ctx, &wbuf)) {
        case 0:
            /* write response to socks client. */
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_sclient,
                &wbuf, 1, on_sclient_write);

            /* 'iob' free later. */
            return;
        case 1:
            /* write response to socks client. */
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_sclient,
                &wbuf, 1, on_sclient_write);

            /* close this connection. */
            uv_close((uv_handle_t*) stream, on_io_closed);

            /* 'iob' free later. */
            return;
        case -1:
            /* error packet from client, close connection. */
            uv_close((uv_handle_t*) stream, on_io_closed);
            break;
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from SOCKS client: %s, stage %d.",
            uv_err_name((int) nread), ctx->stage);

        if (ctx->stage == STAGE_FORWARD) {
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        }
        uv_close((uv_handle_t*) stream, on_io_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0.
         * just 'return' in this situation.
         */
        if (!buf->base) return;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_sclient_connect(uv_stream_t* stream, int status)
{
    sserver_ctx_t* ctx;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }

    ctx = xlist_alloc_back(&sserver_ctxs);

    uv_tcp_init(loop, &ctx->io_sclient);

    ctx->io_sclient.data = ctx;
    ctx->io_xserver.data = ctx;
    ctx->ref_count = 1;
    ctx->sclient_blocked = 0;
    ctx->xserver_blocked = 0;
    ctx->stage = STAGE_MESSAGE;

    if (uv_accept(stream, (uv_stream_t*) &ctx->io_sclient) == 0) {
        xlog_debug("a SOCKS client connected.");

        uv_tcp_init(loop, &ctx->io_xserver);
        uv_read_start((uv_stream_t*) &ctx->io_sclient,
            on_iobuf_alloc, on_sclient_read);

    } else {
        xlog_error("uv_accept failed.");

        uv_close((uv_handle_t*) &ctx->io_sclient, on_io_closed);
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp v%d.%d, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, s);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -x <ip:port>  "
        "proxy server connect to. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -b <ip:port>  "
        "SOCKS4/SOCKS5 server listen at. (default: 127.0.0.1:%d)\n", DEF_SSERVER_PORT);
    fprintf(stderr, "  -d <devid>    "
        "device id of client connect to. (default: not connect client)\n");
    fprintf(stderr, "  -m <method>   "
        "crypto method with proxy server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   "
        "crypto method with client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -k <password> "
        "crypto password with proxy server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> "
        "crypto password with client. (default: none)\n");
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
    uv_tcp_t io_sserver;
    struct sockaddr_in saddr;
    const char* xserver_str = "127.0.0.1";
    const char* sserver_str = "127.0.0.1";
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int verbose = 0;
    int error, i;

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
        case 'x': xserver_str = arg; continue;
        case 'b': sserver_str = arg; continue;
        case 'd':   devid_str = arg; continue;
        case 'm':      method = atoi(arg); continue;
        case 'M':     methodx = atoi(arg); continue;
        case 'k':      passwd = arg; continue;
        case 'K':     passwdx = arg; continue;
        case 'L':     logfile = arg; continue;
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

    if (parse_ip4_str(sserver_str, DEF_SSERVER_PORT, &saddr) != 0) {
        xlog_error("invalid socks5 server address [%s].", sserver_str);
        goto end;
    }

    uv_tcp_init(loop, &io_sserver);
    uv_tcp_bind(&io_sserver, (struct sockaddr*) &saddr, 0);

    error = uv_listen((uv_stream_t*) &io_sserver,
                LISTEN_BACKLOG, on_sclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.",
            addr_to_str(&saddr), uv_strerror(error));
        goto end;
    }

    xlist_init(&sserver_ctxs, sizeof(sserver_ctx_t), NULL);
    xlist_init(&io_buffers, sizeof(io_buf_t), NULL);
    xlist_init(&conn_reqs, sizeof(uv_connect_t), NULL);

    xlog_info("proxy server [%s].", addr_to_str(&xserver_addr));
    xlog_info("SOCKS server listen at [%s]...", addr_to_str(&saddr));
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&conn_reqs);
    xlist_destroy(&io_buffers);
    xlist_destroy(&sserver_ctxs);
end:
    xlog_info("end of loop.");
    xlog_exit();

    return 0;
}