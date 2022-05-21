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
#ifdef __linux__
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#endif

#include "xclient.h"

/*  --------------         --------------         --------------
 * | proxy-server | <---> | proxy-client | <---> | applications |
 *  --------------         --------------         --------------
 *                         (tunnel-server)        (tunnel-client)
 */

static union { cmd_t m; u8_t _[CMD_MAX_SIZE]; } tunnel_maddr;
static union { uv_tcp_t t; uv_udp_t u; } io_tserver; /* tunnel server listen io */

/* override */ void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xclient_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;
        xlog_debug("%zd bytes from tunnel client, to proxy server.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
            &wbuf, 1, on_xserver_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_xserver) > MAX_WQUEUE_SIZE) {
            xlog_debug("proxy server write queue pending.");

            /* stop reading from tunnel client until proxy server write queue cleared. */
            uv_read_stop(stream);
            ctx->xclient_blocked = 1;
        }
        /* 'iob' free later. */
        return;
    }

    if (nread < 0) {
        xlog_debug("disconnected from tunnel client: %s.", uv_err_name((int) nread));

        uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        /* 'stream' with NULL 'close_cb' MUST be closed after 'io_xserver'. */
        uv_close((uv_handle_t*) stream, NULL);

        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

static void on_tclient_connect(uv_stream_t* stream, int status)
{
    xclient_ctx_t* ctx;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }
    ctx = xlist_alloc_back(&xclient.xclient_ctxs);

    uv_tcp_init(xclient.loop, &ctx->xclient.t.io);

    ctx->xclient.t.io.data = ctx;
    ctx->io_xserver.data = ctx;
    ctx->is_udp = 0;
    ctx->pending_iob = NULL;
    ctx->xclient_blocked = 0;
    ctx->xserver_blocked = 0;
    ctx->stage = STAGE_INIT;

    if (uv_accept(stream, (uv_stream_t*) &ctx->xclient.t.io) == 0) {
        xlog_debug("tunnel client connected.");
#ifdef __linux__
        if (tunnel_maddr.m.len) {
#endif
            init_connect_command(ctx, tunnel_maddr.m.cmd,
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

            if (getsockopt(ctx->xclient.t.io.io_watcher.fd,
                    SOL_IP, SO_ORIGINAL_DST, &dest, &len) == 0) {
                init_connect_command(ctx, CMD_CONNECT_IPV4,
                    dest.v4.sin_port, (u8_t*) &dest.v4.sin_addr, 4);

            } else if (getsockopt(ctx->xclient.t.io.io_watcher.fd,
                    SOL_IPV6, IP6T_SO_ORIGINAL_DST, &dest, &len) == 0) {
                init_connect_command(ctx, CMD_CONNECT_IPV6,
                    dest.v6.sin6_port, (u8_t*) &dest.v6.sin6_addr, 16);

            } else {
                xlog_warn("getsockopt IP6T_SO_ORIGINAL_DST failed: %s.",
                    strerror(errno));
                uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
                return;
            }
        }
#endif
        uv_tcp_init(xclient.loop, &ctx->io_xserver);

        if (connect_xserver(ctx) != 0) {
            /* connect failed immediately, just close this connection. */
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
            /* 'xclient.t.io' with NULL 'close_cb' MUST be closed after 'io_xserver'. */
            uv_close((uv_handle_t*) &ctx->xclient.t.io, NULL);
        } else {
            /* keepalive with tunnel client. */
            uv_tcp_keepalive(&ctx->xclient.t.io, 1, KEEPIDLE_TIME);
        }
    } else {
        xlog_error("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
    }
}

static void on_udp_tclient_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xclient.io_buffers);

    /* leave 'sizeof(udp_cmd_t) + 2 + tunnel_maddr.m.len' bytes space at the beginnig.  */
    buf->base = iob->buffer + sizeof(udp_cmd_t) + 2 + tunnel_maddr.m.len;
    buf->len = MAX_SOCKBUF_SIZE - sizeof(udp_cmd_t) - 2 - tunnel_maddr.m.len;
}

static void on_udp_tclient_read(uv_udp_t* io, ssize_t nread, const uv_buf_t* buf,
        const struct sockaddr* addr, unsigned int flags)
{
    io_buf_t* iob = xcontainer_of(buf->base - sizeof(udp_cmd_t) - 2 - tunnel_maddr.m.len, 
                        io_buf_t, buffer);

    if (nread < 0) {
        xlog_warn("udp tunnel client read failed: %s.", uv_err_name((int) nread));

    } else if (!addr) {
        /* 'nread' == 0 and 'addr' == NULL means no more data. */
        xlog_debug("udp tunnel client read nothing.");

    } else if (flags & UV_UDP_PARTIAL) {
        xlog_warn("tunnel client udp packet too large (> %u), drop it.", buf->len);

    } else {
        udp_cmd_t* cmd = (udp_cmd_t*) iob->buffer;

        cmd->tag = CMD_TAG;
        cmd->id = get_udp_packet_id(addr);

        switch (tunnel_maddr.m.len) {
        case 4:
            cmd->alen = 4;
            cmd->len = htons(nread + 4 + 2);
            memcpy(cmd->data, tunnel_maddr.m.data, 4);
            memcpy(cmd->data + 4, &tunnel_maddr.m.port, 2);
            iob->len = nread + 4 + 2 + sizeof(udp_cmd_t);
            break;
        default: /* 16 */
            cmd->alen = 16;
            cmd->len = htons(nread + 16 + 2);
            memcpy(cmd->data, tunnel_maddr.m.data, 16);
            memcpy(cmd->data + 16, &tunnel_maddr.m.port, 2);
            iob->len = nread + 16 + 2 + sizeof(udp_cmd_t);
            break;
        }

        xlog_debug("send udp packet to proxy server, %u bytes, id %x.",
            iob->len, cmd->id);
        send_udp_packet(iob);
        /* 'iob' free later. */
        return;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

/* override */ void recv_udp_packet(udp_cmd_t* cmd)
{
    const struct sockaddr* addr = get_udp_packet_saddr(cmd->id);
    uv_buf_t wbuf;

    if (!addr) {
        xlog_warn("udp packet id (%x) not found.", cmd->id);
        return;
    }
    wbuf.base = (char*) cmd + cmd->alen + 2 + sizeof(udp_cmd_t);
    wbuf.len = ntohs(cmd->len) - cmd->alen - 2;

    xlog_debug("send udp packet to tunnel client [%s], %u bytes.",
        addr_to_str(addr), wbuf.len);

    if (uv_udp_try_send(&io_tserver.u, &wbuf, 1, addr) < 0) {
        xlog_debug("send udp packet to tunnel client failed.");
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
    fprintf(stderr, "trp v%d.%d.%d, libuv %s, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, uv_version_string(), s);
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
    fprintf(stderr, "  -u <number>   set the number of UDP-over-TCP connection pools and disable TCP tunnel mode. (default: 0)\n");
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
    int nconnect = 0;
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
        case 'u':    nconnect = atoi(arg); continue;
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
    seed_rand((u32_t) time(NULL));

    xclient_private_init();
    xclient.loop = uv_default_loop();

    if (nconnect < 0 || nconnect > 1024) {
        xlog_warn("invalid connection pool size [%d], reset to [1].", nconnect);
        nconnect = 1;
    }

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
                || resolve_domain_sync(xclient.loop, &dm, &xclient.xserver_addr.x) != 0) {
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
        if (nconnect) {
            xlog_error("udp transparent proxy mode is not supported currently.");
            goto end;
        }
        xlog_info("enter tcp transparent proxy mode.");
#else
        xlog_error("tunnel address (-t) must be specified on !linux.");
        goto end;
#endif
    } else if (init_tunnel_maddr(tunnel_str) != 0) {
        xlog_error("invalid tunnel address [%s].", tunnel_str);
        goto end;
    } else {
        xlog_info("tunnel to [%s].", maddr_to_str(&tunnel_maddr.m));
    }

    if (!nconnect) {
        /* TCP mode. */
        xlog_info("enter tcp tunnel mode.");
        uv_tcp_init(xclient.loop, &io_tserver.t);
        uv_tcp_bind(&io_tserver.t, &taddr.x, 0);

        error = uv_listen((uv_stream_t*) &io_tserver.t, LISTEN_BACKLOG, on_tclient_connect);
        if (error) {
            xlog_error("uv_listen [%s] failed: %s.", addr_to_str(&taddr), uv_strerror(error));
            goto end;
        }
    } else if (tunnel_maddr.m.cmd != CMD_CONNECT_DOMAIN) {
        /* UDP mode. */
        xlog_info("enter udp tunnel mode.");
        uv_udp_init(xclient.loop, &io_tserver.u);
        uv_udp_bind(&io_tserver.u, &taddr.x, 0);

        error = uv_udp_recv_start(&io_tserver.u, on_udp_tclient_rbuf_alloc,
                    on_udp_tclient_read);
        if (error) {
            xlog_error("uv_udp_recv_start [%s] failed: %s.", addr_to_str(&taddr),
                uv_strerror(error));
            goto end;
        }
        xclient.n_uconnect = nconnect;
    } else {
        xlog_error("udp tunnel to domain is not supported.");
        goto end;
    }

    xlist_init(&xclient.xclient_ctxs, sizeof(xclient_ctx_t), NULL);
    xlist_init(&xclient.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);

    xlog_info("proxy server [%s].", addr_to_str(&xclient.xserver_addr));
    xlog_info("tunnel server listen at [%s]...", addr_to_str(&taddr));
    uv_run(xclient.loop, UV_RUN_DEFAULT);

    xlist_destroy(&xclient.io_buffers);
    xlist_destroy(&xclient.xclient_ctxs);
end:
    xlog_info("end of loop.");
    xclient_private_destroy();
    xlog_exit();

    return 0;
}