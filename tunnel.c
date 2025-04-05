/*
 * Copyright (C) 2021-2025 nonikon@qq.com.
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
static uv_udp_t io_utserver; /* udp tunnel server listen io */

/* override */ void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xclient_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;
        XLOGD("%zd bytes from tunnel client, to proxy server.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
            &wbuf, 1, on_xserver_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_xserver) > MAX_WQUEUE_SIZE) {
            XLOGD("proxy server write queue pending.");

            /* stop reading from tunnel client until proxy server write queue cleared. */
            uv_read_stop(stream);
            ctx->xclient_blocked = 1;
        }
        /* 'iob' free later. */
        return;
    }

    if (nread < 0) {
        XLOGD("disconnected from tunnel client: %s.", uv_err_name((int) nread));

        uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        uv_close((uv_handle_t*) stream, on_io_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

static void on_tclient_connect(uv_stream_t* stream, int status)
{
    xclient_ctx_t* ctx;

    if (status < 0) {
        XLOGE("new connection error: %s.", uv_strerror(status));
        return;
    }
    ctx = xlist_alloc_back(&xclient.xclient_ctxs);

    uv_tcp_init(xclient.loop, &ctx->xclient.t.io);

    ctx->xclient.t.io.data = ctx;
    ctx->io_xserver.data = ctx;
    ctx->ref_count = 1;
    ctx->is_udp = 0;
    ctx->pending_iob = NULL;
    ctx->xclient_blocked = 0;
    ctx->xserver_blocked = 0;
    ctx->stage = STAGE_INIT;

    if (uv_accept(stream, (uv_stream_t*) &ctx->xclient.t.io) == 0) {
        XLOGD("tunnel client connected.");
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
                XLOGW("getsockopt IP6T_SO_ORIGINAL_DST failed: %s.",
                    strerror(errno));
                uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
                return;
            }
        }
#endif
        uv_tcp_init(xclient.loop, &ctx->io_xserver);
        /* 'ctx->io_xserver' need to be closed, increase refcount. */
        ctx->ref_count = 2;

        if (connect_xserver(ctx) != 0) {
            /* connect failed immediately, just close this connection. */
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
            uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
        } else {
            /* keepalive with tunnel client. */
            uv_tcp_keepalive(&ctx->xclient.t.io, 1, KEEPIDLE_TIME);
        }
    } else {
        XLOGE("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
    }
}

static void on_udp_tclient_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xclient.io_buffers);

    /* leave 'sizeof(udp_cmd_t) + 2 + tunnel_maddr.m.len' bytes space at the beginning. */
    buf->base = iob->buffer + sizeof(udp_cmd_t) + 2 + tunnel_maddr.m.len;
    buf->len = MAX_SOCKBUF_SIZE - sizeof(udp_cmd_t) - 2 - tunnel_maddr.m.len;
}

static void on_udp_tclient_read(uv_udp_t* io, ssize_t nread, const uv_buf_t* buf,
        const struct sockaddr* addr, unsigned int flags)
{
    io_buf_t* iob = xcontainer_of(buf->base - sizeof(udp_cmd_t) - 2 - tunnel_maddr.m.len,
                        io_buf_t, buffer);

    if (nread < 0) {
        XLOGW("udp tunnel client read failed: %s.", uv_err_name((int) nread));

    } else if (!addr) {
        /* 'nread' == 0 and 'addr' == NULL means no more data. */
        XLOGD("udp tunnel client read nothing.");

    } else if (flags & UV_UDP_PARTIAL) {
        XLOGW("tunnel client udp packet too large (> %u), drop it.", buf->len);

    } else {
        udp_cmd_t* cmd = (udp_cmd_t*) iob->buffer;

        cmd->flag = xclient.utimeo;
        cmd->id = get_udp_packet_id(addr);

        switch (tunnel_maddr.m.len) {
        case 4:
            cmd->alen = 4;
            cmd->len = htons((u16_t) (nread + 4 + 2));
            memcpy(cmd->data, tunnel_maddr.m.data, 4);
            memcpy(cmd->data + 4, &tunnel_maddr.m.port, 2);
            iob->len = (u32_t) (nread + 4 + 2 + sizeof(udp_cmd_t));
            break;
        default: /* 16 */
            cmd->alen = 16;
            cmd->len = htons((u16_t) (nread + 16 + 2));
            memcpy(cmd->data, tunnel_maddr.m.data, 16);
            memcpy(cmd->data + 16, &tunnel_maddr.m.port, 2);
            iob->len = (u32_t) (nread + 16 + 2 + sizeof(udp_cmd_t));
            break;
        }

        XLOGD("%u udp bytes from tunnel client, to proxy server id %x.",
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
        XLOGW("udp packet id (%x) not found.", cmd->id);
        return;
    }
    wbuf.base = (char*) cmd + cmd->alen + 2 + sizeof(udp_cmd_t);
    wbuf.len = ntohs(cmd->len) - cmd->alen - 2;

    XLOGD("%u udp bytes to tunel client (%s).", wbuf.len, addr_to_str(addr));

    if (uv_udp_try_send(&io_utserver, &wbuf, 1, addr) < 0) {
        XLOGD("send udp packet to tunnel client failed.");
    }
}

static int init_tunnel_maddr(const char* addrstr, int allow_domain)
{
    union {
        struct sockaddr     dx;
        struct sockaddr_in  d4;
        struct sockaddr_in6 d6;
        struct sockaddr_dm  dm;
    } _;

    if (parse_ip_str(addrstr, -1, &_.dx) != 0) {
        if (parse_domain_str(addrstr, -1, &_.dm) != 0) {
            /* not a valid 'ip:port' or 'domain:port' string. */
            return -1;
        }
        if (!allow_domain) {
            XLOGI("UDP tunnel to domain is not supported, resolve it...");

            if (resolve_domain_sync(xclient.loop, &_.dm, &_.dx) != 0) {
                XLOGE("resolve domain (%s) failed.", _.dm.sdm_addr);
                return -1;
            }
        }
    }

    switch (_.dx.sa_family) {
    case AF_INET:
        tunnel_maddr.m.cmd = CMD_CONNECT_IPV4;
        tunnel_maddr.m.len = 4;
        tunnel_maddr.m.port = _.d4.sin_port;
        memcpy(tunnel_maddr.m.data, &_.d4.sin_addr, 4);
        break;

    case AF_INET6:
        tunnel_maddr.m.cmd = CMD_CONNECT_IPV6;
        tunnel_maddr.m.len = 16;
        tunnel_maddr.m.port = _.d6.sin6_port;
        memcpy(tunnel_maddr.m.data, &_.d6.sin6_addr, 16);
        break;

    default: /* 0 - DOMAIN */
        tunnel_maddr.m.cmd = CMD_CONNECT_DOMAIN;
        tunnel_maddr.m.len = (u8_t) (strlen(_.dm.sdm_addr) + 1);
        tunnel_maddr.m.port = _.dm.sdm_port;
        memcpy((char*) tunnel_maddr.m.data, _.dm.sdm_addr,
            tunnel_maddr.m.len);
        break;
    }

    return 0;
}

static void usage(const char* s)
{
    fprintf(stderr, "trp %s libuv %s, usage: %s [option]...\n", version_string(), uv_version_string(), s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -x <address>  proxy server connect to. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -b <address>  tunnel server listen at. (default: 127.0.0.1:%d)\n", DEF_TSERVER_PORT);
#ifdef __linux__
    fprintf(stderr, "  -t <address>  target tunnel to. (default: transparent proxy mode)\n");
#else
    fprintf(stderr, "  -t <address>  target tunnel to.\n");
#endif
    fprintf(stderr, "  -d <devid>    device id (1~16 bytes string) of client connect to. (default: not connect client)\n");
    fprintf(stderr, "  -k <password> crypto password with proxy server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> crypto password with client. (default: none)\n");
    fprintf(stderr, "  -m <method>   crypto method with proxy server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   crypto method with client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -a <number>   prefer addr type used in remote domain resolution, 0 - none, 1 - IPV4, 2 - IPV6. (default: 0)\n");
    fprintf(stderr, "  -u <number>   set the number of UDP-over-TCP connection pools. (default: 0)\n");
    fprintf(stderr, "  -U <NUMBER>   set the number of UDP-over-TCP connection pools and disable TCP tunnel. (default: 0)\n");
    fprintf(stderr, "  -O <number>   set UDP connection timeout seconds. (default: %d)\n", UDPCONN_TIMEO);
    fprintf(stderr, "                set a negative number to enable close-on-recv feature. (recommended for DNS relay)\n");
#ifndef _WIN32
    fprintf(stderr, "  -n <number>   set max number of open files.\n");
#endif
    fprintf(stderr, "  -l <path>     write output to file. (default: write to STDOUT)\n");
    fprintf(stderr, "  -L <path>     write output to file and run as daemon. (default: write to STDOUT)\n");
    fprintf(stderr, "  -C <config>   set config file path and section. (default: trp.ini)\n");
    fprintf(stderr, "                section can be specified after colon. (default: trp.ini:tunnel)\n");
    fprintf(stderr, "  -v            output verbosely.\n");
    fprintf(stderr, "  -V            output version string.\n");
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
    uv_tcp_t io_tserver; /* tcp tunner server listen io */
    union { struct sockaddr x; struct sockaddr_in6 d; } taddr;
    char* cfg_path = NULL;
    const char* cfg_sec = "tunnel";
    const char* xserver_str = "127.0.0.1";
    const char* tserver_str = "127.0.0.1";
    const char* tunnel_str = NULL;
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int daemonize = 0;
    int cfg_specified = 0;
#ifdef _WIN32
    int is_childproc = 0;
#else
    int nofile = 0;
#endif
    int addrpref = 0;
    int utimeo = UDPCONN_TIMEO;
    int nconnect = 0; /* the number of UDP-over-TCP connections */
    int tcpoff = 0;
    int verbose = 0;
    int error;
    int i;

    for (i = 1; i < argc; ++i) {
        char* opt = argv[i];
        char* arg;

        if (opt[0] != '-') {
            /* argument only. (opt) */
            fprintf(stderr, "%s: invalid parameter [%s].\n", argv[0], opt);
            return 1;
        }

        if (opt[1] != '-') {
            opt = opt + 1;

            /* short option without argument. (-opt[0]) */
            switch (opt[0]) {
            case 'v': verbose = 1; continue;
            case 'V':
                fprintf(stderr, "trp %s libuv %s.\n", version_string(), uv_version_string());
                return 1;
            case 'h':
                usage(argv[0]);
                return 1;
            case '\0':
                fprintf(stderr, "%s: invalid parameter [-].\n", argv[0]);
                return 1;
            }

            arg = opt[1] ? opt + 1 : (++i < argc ? argv[i] : NULL);
            if (!arg) {
                fprintf(stderr, "%s: invalid parameter [-%c].\n", argv[0], opt[0]);
                return 1;
            }

            /* short option with argument. (-opt[0] arg) */
            switch (opt[0]) {
            case 'x': xserver_str = arg; continue;
            case 'b': tserver_str = arg; continue;
            case 't':  tunnel_str = arg; continue;
            case 'd':   devid_str = arg; continue;
            case 'm':      method = atoi(arg); continue;
            case 'M':     methodx = atoi(arg); continue;
            case 'k':      passwd = arg; continue;
            case 'K':     passwdx = arg; continue;
            case 'a':    addrpref = atoi(arg); continue;
            case 'u':    nconnect = atoi(arg); tcpoff = 0; continue;
            case 'U':    nconnect = atoi(arg); tcpoff = 1; continue;
            case 'O':      utimeo = atoi(arg); continue;
#ifndef _WIN32
            case 'n':      nofile = atoi(arg); continue;
#endif
            case 'l':     logfile = arg;     daemonize = 0; continue;
            case 'L':     logfile = arg;     daemonize = 1; continue;
            case 'C':    cfg_path = arg; cfg_specified = 1; continue;
            }

            fprintf(stderr, "%s: invalid parameter [-%c %s].\n", argv[0], opt[0], arg);
            return 1;
        }
        opt = opt + 2;

        /* long option without argument. (--opt) */
#ifdef _WIN32
        if (!strcmp(opt, "child")) { /* --child is for internal use only */
            is_childproc = 1;
            continue;
        }
#endif

        arg = ++i < argc ? argv[i] : NULL;
        if (!arg) {
            fprintf(stderr, "%s: invalid parameter [--%s].\n", argv[0], opt);
            return 1;
        }

        /* long option with argument. (--opt arg) */

        fprintf(stderr, "%s: invalid parameter [--%s %s].\n", argv[0], opt, arg);
        return 1;
    }

    xlog_init(NULL); /* output to STDOUT first */

    i = 0;
    parse_config_str(&cfg_path, &cfg_sec);
    error = load_config_file(cfg_path, cfg_sec);
    if (error < 0) {
        if (cfg_specified) {
            XLOGE("open config file (%s) failed, exit.", cfg_path);
            return 1;
        }
    } else if (error > 0) {
        XLOGE("error at config file %s:%d, ignore configs.", cfg_path, error);
    } else {
        config_item_t* item = NULL;

        while (!!(item = get_config_item(item))) {
            if (!item->name[0] || !item->value[0]) {
                XLOGW("invalid config item (%s=%s), ignore.", item->name, item->value);
                continue;
            } else if (!strcmp(item->name, "v")) { verbose = atoi(item->value);
            } else if (!strcmp(item->name, "x")) { xserver_str = item->value;
            } else if (!strcmp(item->name, "b")) { tserver_str = item->value;
            } else if (!strcmp(item->name, "t")) { tunnel_str = item->value;
            } else if (!strcmp(item->name, "d")) { devid_str = item->value;
            } else if (!strcmp(item->name, "m")) { method = atoi(item->value);
            } else if (!strcmp(item->name, "M")) { methodx = atoi(item->value);
            } else if (!strcmp(item->name, "k")) { passwd = item->value;
            } else if (!strcmp(item->name, "K")) { passwdx = item->value;
            } else if (!strcmp(item->name, "a")) { addrpref = atoi(item->value);
            } else if (!strcmp(item->name, "u")) { nconnect = atoi(item->value); tcpoff = 0;
            } else if (!strcmp(item->name, "U")) { nconnect = atoi(item->value); tcpoff = 1;
            } else if (!strcmp(item->name, "O")) { utimeo = atoi(item->value);
#ifndef _WIN32
            } else if (!strcmp(item->name, "n")) { nofile = atoi(item->value);
#endif
            } else if (!strcmp(item->name, "l")) { logfile = item->value; daemonize = 0;
            } else if (!strcmp(item->name, "L")) { logfile = item->value; daemonize = 1;
            } else {
                XLOGW("invalid config item name (%s), ignore.", item->name);
                continue;
            }
            ++i;
        }
    }

    if (logfile) {
        XLOGI("switch output to file: %s...", logfile);
        if (xlog_init(logfile) != 0) {
            XLOGE("open logfile failed, switch to stdout.");
        }
    }

#ifdef _WIN32
    if (daemonize && !is_childproc) {
        xlog_exit(); /* close log file */
        if (daemon(argc, argv) != 0) {
            xlog_init(logfile); /* reopen log file when daemon failed */
            XLOGE("run as daemon failed: %u", GetLastError());
        }
    }
#else
    if (daemonize && daemon(1, 0) != 0) {
        XLOGE("run as daemon failed: %s.", strerror(errno));
    }
#endif
    XLOGI("current version %s, libuv %s.", version_string(), uv_version_string());
    if (!verbose) {
        xlog_ctrl(XLOG_INFO, 0, 0);
    } else {
        XLOGI("enable verbose output.");
    }
    if (i > 0) {
        XLOGI("load %d item(s) from config file (%s:%s).", i, cfg_path, cfg_sec);
    }
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);

    if (nofile > 1024) {
        struct rlimit limit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            XLOGW("set NOFILE limit to %d failed: %s.", nofile, strerror(errno));
        } else {
            XLOGI("set NOFILE limit to %d.", nofile);
        }
    }
#endif
    seed_rand((u32_t) time(NULL));

    xclient_private_init();
    xclient.loop = uv_default_loop();

    if (nconnect < 0 || nconnect > 1024) {
        XLOGW("invalid connection pool size (%d), reset to 1.", nconnect);
        nconnect = 1;
    }
    if (addrpref > FLG_ADDRPREF_IPV6) {
        XLOGW("invalid prefer addr type (%d), reset to 0.", addrpref);
        addrpref = FLG_ADDRPREF_NONE;
    }
    xclient.addrpref = addrpref;

    if (utimeo < 0) {
        XLOGI("UDP flag close-on-recv ON.");
        utimeo = -utimeo;
        xclient.utimeo = 0x80;
    } else {
        xclient.utimeo = 0;
    }
    if (utimeo > MAX_UDPCONN_TIMEO) {
        XLOGW("invalid UDP connection timeout (%d), reset to %d.",
            utimeo, UDPCONN_TIMEO);
        utimeo = UDPCONN_TIMEO;
    }
    xclient.utimeo |= (u8_t) utimeo; /* utimeo == 0 is allowed */

    if (devid_str && str_to_devid(xclient.device_id, devid_str) != 0) {
        XLOGE("invalid device id string (%s).", devid_str);
        goto end;
    }

    if (passwd) {
        derive_key(xclient.crypto_key, passwd);
    } else {
        XLOGI("password not set, disable crypto with proxy server.");
        method = CRYPTO_NONE;
    }
    if (devid_str) {
        if (passwdx) {
            derive_key(xclient.cryptox_key, passwdx);
        } else {
            XLOGI("PASSWORD (-K) not set, disable crypto with client.");
            methodx = CRYPTO_NONE;
        }
    } else {
        if (passwdx) {
            XLOGI("device id not set, ignore PASSWORD (-K).");
        }
        methodx = method;
        memcpy(xclient.cryptox_key, xclient.crypto_key, 16);
    }

    if (crypto_init(&xclient.crypto, method) != 0) {
        XLOGE("invalid crypto method (%d).", method);
        goto end;
    }
    if (crypto_init(&xclient.cryptox, methodx) != 0) {
        XLOGE("invalid crypto METHOD (%d).", methodx);
        goto end;
    }
    XLOGI("crypto method %d, METHOD %d.", method, methodx);

    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xclient.xserver_addr.x) != 0) {
        struct sockaddr_dm dm;

        if (parse_domain_str(xserver_str, DEF_XSERVER_PORT, &dm) != 0) {
            XLOGE("invalid proxy server address (%s).", xserver_str);
            goto end;
        }
        if (resolve_domain_sync(xclient.loop, &dm, &xclient.xserver_addr.x) != 0) {
            XLOGE("resolve domain (%s) failed.", xserver_str);
            goto end;
        }
    }

    if (parse_ip_str(tserver_str, DEF_TSERVER_PORT, &taddr.x) != 0) {
        XLOGE("invalid tunnel server address (%s).", tserver_str);
        goto end;
    }

    if (tunnel_str) {
        /* tunnel mode. (udp tunnel to domain is not allowed) */
        if (init_tunnel_maddr(tunnel_str, 0 == nconnect) != 0) {
            XLOGE("invalid tunnel address (%s).", tunnel_str);
            goto end;
        }

        if (nconnect) {
            XLOGI("enable UDP tunnel mode, connections %d, timeout %d.", nconnect, utimeo);
            uv_udp_init(xclient.loop, &io_utserver);

            error = uv_udp_bind(&io_utserver, &taddr.x, 0);
            if (error) {
                XLOGE("udp bind (%s) failed: %s.", addr_to_str(&taddr),
                    uv_strerror(error));
                goto end;
            }
            error = uv_udp_recv_start(&io_utserver, on_udp_tclient_rbuf_alloc,
                        on_udp_tclient_read);
            if (error) {
                XLOGE("udp listen (%s) failed: %s.", addr_to_str(&taddr),
                    uv_strerror(error));
                goto end;
            }
            xclient.n_uconnect = nconnect;
        } else {
            tcpoff = 0;
        }

        if (!tcpoff) {
            XLOGI("enable TCP tunnel mode.");
            uv_tcp_init(xclient.loop, &io_tserver);

            error = uv_tcp_bind(&io_tserver, &taddr.x, 0);
            if (error) {
                XLOGE("tcp bind (%s) failed: %s.", addr_to_str(&taddr),
                    uv_strerror(error));
                goto end;
            }
            error = uv_listen((uv_stream_t*) &io_tserver, LISTEN_BACKLOG,
                        on_tclient_connect);
            if (error) {
                XLOGE("tcp listen (%s) failed: %s.", addr_to_str(&taddr),
                    uv_strerror(error));
                goto end;
            }
        }
        XLOGI("tunnel to %s.", maddr_to_str(&tunnel_maddr.m));
    } else {
        /* transparent mode. */
#ifdef __linux__
        if (nconnect) {
            /* TPROXY, TODO */
            XLOGE("UDP transparent proxy mode is not supported.");
            goto end;
        }
        XLOGI("enable TCP transparent proxy mode.");

        uv_tcp_init(xclient.loop, &io_tserver);

        error = uv_tcp_bind(&io_tserver, &taddr.x, 0);
        if (error) {
            XLOGE("tcp bind (%s) failed: %s.", addr_to_str(&taddr),
                uv_strerror(error));
            goto end;
        }
        error = uv_listen((uv_stream_t*) &io_tserver, LISTEN_BACKLOG,
                    on_tclient_connect);
        if (error) {
            XLOGE("tcp listen (%s) failed: %s.", addr_to_str(&taddr),
                uv_strerror(error));
            goto end;
        }
#else
        XLOGE("tunnel address (-t) must be specified.");
        goto end;
#endif
    }

    xlist_init(&xclient.xclient_ctxs, sizeof(xclient_ctx_t), NULL);
    xlist_init(&xclient.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);

    XLOGI("proxy server: %s.", addr_to_str(&xclient.xserver_addr));
    if (devid_str) {
        XLOGI("to device id: %s.", devid_to_str(xclient.device_id));
    }
    if (addrpref) {
        XLOGI("prefer addr type: %d.", addrpref);
    }
    XLOGI("tunnel server listen at %s...", addr_to_str(&taddr));
    uv_run(xclient.loop, UV_RUN_DEFAULT);

    xlist_destroy(&xclient.io_buffers);
    xlist_destroy(&xclient.xclient_ctxs);
end:
    XLOGI("end of loop.");
    xclient_private_destroy();
    xlog_exit();

    return 0;
}