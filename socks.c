/*
 * Copyright (C) 2021-2022 nonikon@qq.com.
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

#include "xclient.h"

/*  --------------         --------------         --------------
 * | proxy-server | <---> | proxy-client | <---> | applications |
 *  --------------         --------------         --------------
 *                         (socks-server)         (socks-client)
 *
 * SOCKS5 Protocol: https://www.ietf.org/rfc/rfc1928.txt
 */

static uv_loop_t* loop;

/* SOCKS4/SOCKS5 handshake */
static int socks_handshake(xclient_ctx_t* ctx, uv_buf_t* buf)
{
    if (ctx->stage == STAGE_INIT) {

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

            init_connect_command(ctx, CMD_CONNECT_IPV4,
                *(u16_t*) (buf->base + 2), (u8_t*) (buf->base + 4), 4);

            buf->base[0] = 0x00; /* set 'VN' to 0x00 */
            buf->len = 8;

            if (connect_xserver(ctx) == 0) {
                /* assume that proxy server was connected successfully. */

                /* stop reading from socks client until proxy server connected. */
                uv_read_stop((uv_stream_t*) &ctx->io_xclient);

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
                    init_connect_command(ctx, CMD_CONNECT_IPV4,
                        *(u16_t*) (buf->base + 8), (u8_t*) (buf->base + 4), 4);
                    buf->base[1] = 0x00;
                } else {
                    xlog_warn("socks5 IPV4 request packet len (%d) error.", buf->len);
                    buf->base[1] = 0x01;
                }

            } else if (buf->base[3] == 0x03) { /* 'ATYP' == 0x03 (DOMAINNAME) */
                u32_t l = buf->base[4] & 0xff;

                if (l < MAX_DOMAIN_LEN && buf->len == 6 + 1 + l) {
                    u16_t port = *(u16_t*) (buf->base + l + 5);

                    buf->base[5 + l] = 0; /* make domain name null-terminated. */
                    init_connect_command(ctx, CMD_CONNECT_DOMAIN,
                        port, (u8_t*) (buf->base + 5), l + 1);
                    buf->base[1] = 0x00;
                } else {
                    xlog_warn("socks5 request packet len error, domain len %d.", l);
                    buf->base[1] = 0x01;
                }

            } else if (buf->base[3] == 0x04) { /* 'ATYP' == 0x04 (IPV6) */

                if (buf->len == 6 + 16) {
                    init_connect_command(ctx, CMD_CONNECT_IPV6,
                        *(u16_t*) (buf->base + 20), (u8_t*) (buf->base + 4), 16);
                    buf->base[1] = 0x00;
                } else {
                    xlog_warn("socks5 IPV6 request packet len (%d) error.", buf->len);
                    buf->base[1] = 0x01;
                }

            } else {
                xlog_warn("unsupported socks5 address type %d.", buf->base[3]);
                buf->base[1] = 0x08;
            }

            if (buf->base[1] == 0x00) { /* no error */

                if (connect_xserver(ctx) == 0) {
                    /* assume that proxy server was connected successfully. */

                    /* zero BIND.ADDR and BIND.PORT. uv_tcp_getsockname() maybe better. */
                    memset(buf->base + 4, 0, 6);

                    /* stop reading from socks client until proxy server connected. */
                    uv_read_stop((uv_stream_t*) &ctx->io_xclient);

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

/* override */ void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xclient_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        if (ctx->stage == STAGE_FORWARDTCP) {

            xlog_debug("recved %zd bytes from SOCKS client, forward.", nread);

            xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
                &wbuf, 1, on_xserver_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_xserver) > MAX_WQUEUE_SIZE) {
                xlog_debug("proxy server write queue pending.");

                /* stop reading from SOCKS client until proxy server write queue cleared. */
                uv_read_stop(stream);
                ctx->xclient_blocked = 1;
            }

            /* 'iob' free later. */
            return;
        }

        switch (socks_handshake(ctx, &wbuf)) {
        case 0:
            /* write response to socks client. */
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xclient,
                &wbuf, 1, on_xclient_write);

            /* 'iob' free later. */
            return;
        case 1:
            /* write response to socks client. */
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xclient,
                &wbuf, 1, on_xclient_write);

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

        if (ctx->stage == STAGE_FORWARDTCP) {
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        }
        uv_close((uv_handle_t*) stream, on_io_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0.
         * just 'return' in this situation.
         */
        if (!buf->base) return;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

static void on_sclient_connect(uv_stream_t* stream, int status)
{
    xclient_ctx_t* ctx;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }

    ctx = xlist_alloc_back(&xclient.xclient_ctxs);

    uv_tcp_init(loop, &ctx->io_xclient);

    ctx->io_xclient.data = ctx;
    ctx->io_xserver.data = ctx;
    ctx->pending_iob = NULL;
    ctx->ref_count = 1;
    ctx->xclient_blocked = 0;
    ctx->xserver_blocked = 0;
    ctx->stage = STAGE_INIT;

    if (uv_accept(stream, (uv_stream_t*) &ctx->io_xclient) == 0) {
        xlog_debug("a SOCKS client connected.");
        uv_tcp_init(loop, &ctx->io_xserver);
        uv_read_start((uv_stream_t*) &ctx->io_xclient, on_iobuf_alloc, on_xclient_read);
    } else {
        xlog_error("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->io_xclient, on_io_closed);
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp v%d.%d.%d, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -x <address>  proxy server connect to. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -b <address>  SOCKS4/SOCKS5 server listen at. (default: 127.0.0.1:%d)\n", DEF_SSERVER_PORT);
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
    uv_tcp_t io_sserver; /* socks server listen io */
    union { struct sockaddr x; struct sockaddr_in6 d; } saddr;
    const char* xserver_str = "127.0.0.1";
    const char* sserver_str = "127.0.0.1";
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
        case 'b': sserver_str = arg; continue;
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

    if (xlog_init(logfile) != 0) {
        fprintf(stderr, "open logfile failed.\n");
    }

    if (!verbose) {
        xlog_ctrl(XLOG_INFO, 0, 0);
    } else {
        xlog_info("enable verbose output.");
    }

#ifndef _WIN32
    if (logfile && daemon(1, 0) != 0) {
        xlog_error("run as daemon failed: %s.", strerror(errno));
    }

    signal(SIGPIPE, SIG_IGN);

    if (nofile > 1024) {
        struct rlimit limit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            xlog_warn("set NOFILE limit to %d failed: %s.", nofile, strerror(errno));
        } else {
            xlog_info("set NOFILE limit to %d.", nofile);
        }
    }
#endif

    loop = uv_default_loop();

    seed_rand((u32_t) time(NULL));

    if (devid_str && str_to_devid(xclient.device_id, devid_str) != 0) {
        xlog_error("invalid device id string [%s].", devid_str);
        goto end;
    }

    if (passwd) {
        derive_key(xclient.crypto_key, passwd);
    } else {
        xlog_info("password not set, disable crypto with proxy server.");
        method = CRYPTO_NONE;
    }
    if (devid_str) {
        if (passwdx) {
            derive_key(xclient.cryptox_key, passwdx);
        } else {
            xlog_info("PASSWORD (-K) not set, disable crypto with client.");
            methodx = CRYPTO_NONE;
        }
    } else {
        if (passwdx) {
            xlog_info("device id not set, ignore PASSWORD (-K).");
        }
        methodx = method;
        memcpy(xclient.cryptox_key, xclient.crypto_key, 16);
    }

    if (crypto_init(&xclient.crypto, method) != 0) {
        xlog_error("invalid crypto method: %d.", method);
        goto end;
    }
    if (crypto_init(&xclient.cryptox, methodx) != 0) {
        xlog_error("invalid crypto METHOD: %d.", methodx);
        goto end;
    }

    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xclient.xserver_addr.x) != 0) {
        struct sockaddr_dm dm;

        if (parse_domain_str(xserver_str, DEF_XSERVER_PORT, &dm) != 0
                || resolve_domain_sync(loop, &dm, &xclient.xserver_addr.x) != 0) {
            xlog_error("invalid proxy server address [%s].", xserver_str);
            goto end;
        }
    }

    if (parse_ip_str(sserver_str, DEF_SSERVER_PORT, &saddr.x) != 0) {
        xlog_error("invalid socks5 server address [%s].", sserver_str);
        goto end;
    }

    uv_tcp_init(loop, &io_sserver);
    uv_tcp_bind(&io_sserver, &saddr.x, 0);

    error = uv_listen((uv_stream_t*) &io_sserver, LISTEN_BACKLOG, on_sclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", addr_to_str(&saddr), uv_strerror(error));
        goto end;
    }

    xlist_init(&xclient.xclient_ctxs, sizeof(xclient_ctx_t), NULL);
    xlist_init(&xclient.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);
    xlist_init(&xclient.conn_reqs, sizeof(uv_connect_t), NULL);

    xlog_info("proxy server [%s].", addr_to_str(&xclient.xserver_addr));
    xlog_info("SOCKS4/SOCKS5 server listen at [%s]...", addr_to_str(&saddr));
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&xclient.conn_reqs);
    xlist_destroy(&xclient.io_buffers);
    xlist_destroy(&xclient.xclient_ctxs);
end:
    xlog_info("end of loop.");
    xlog_exit();

    return 0;
}