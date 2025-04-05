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

#include "remote.h"

/*  --------         --------------         --------------
 * | remote | <---> | proxy-server | <---> | proxy-client |
 *  --------        |      ^       |        --------------
 *                  |      |       |
 *  --------        |      v       |
 * | client | <---> |   server     |
 *  --------         --------------
 */

/* override */ void on_peer_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    peer_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
#ifdef WITH_CLIREMOTE
        if (ctx->stage == STAGE_FORWARDCLI) {
            uv_buf_t wbuf;
            XLOGD("%zd bytes from proxy client, to client.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->remote;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->remote->c.io,
                &wbuf, 1, on_cli_remote_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->remote->c.io) > MAX_WQUEUE_SIZE) {
                XLOGD("client write queue pending.");

                /* stop reading from peer until client write queue cleared. */
                uv_read_stop(stream);
                ctx->peer_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }
#endif
        if (ctx->stage == STAGE_FORWARDTCP) {
            uv_buf_t wbuf;
            XLOGD("%zd bytes from proxy client, to tcp remote.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->remote;

            remote.crypto.decrypt(&ctx->edctx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->remote->t.io,
                &wbuf, 1, on_tcp_remote_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->remote->t.io) > MAX_WQUEUE_SIZE) {
                XLOGD("remote write queue pending.");

                /* stop reading from peer until remote write queue cleared. */
                uv_read_stop(stream);
                ctx->peer_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }

        if (ctx->stage == STAGE_FORWARDUDP) {
            XLOGD("%zd udp bytes from proxy client.", nread);

            remote.crypto.decrypt(&ctx->edctx, (u8_t*) buf->base, (u32_t) nread);

            iob->idx = 0;
            iob->len = (u32_t) nread;

            if (forward_peer_udp_packets(ctx->remote, iob) == 0) {
                /* 'iob' was processed totally, release now. */
                xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
            }
            return;
        }

        if (ctx->stage == STAGE_COMMAND) {
            iob->len = (u32_t) nread;

            if (invoke_encrypted_peer_command(ctx, iob) != 0) {
                uv_close((uv_handle_t*) stream, on_peer_closed);
            }
            /* 'iob' free later. */
            return;
        }

        /* should not reach here */
        XLOGE("unexpected state happen.");
        return;
    }

    if (nread < 0) {
        XLOGD("disconnected from proxy client: %s, stage %d.",
            uv_err_name((int) nread), ctx->stage);

        uv_close((uv_handle_t*) stream, on_peer_closed);
#ifdef WITH_CLIREMOTE
        if (ctx->stage == STAGE_FORWARDCLI) {
            uv_close((uv_handle_t*) &ctx->remote->c.io, on_cli_remote_closed);
        } else
#endif
        if (ctx->stage == STAGE_FORWARDTCP) {
            uv_close((uv_handle_t*) &ctx->remote->t.io, on_tcp_remote_closed);
        } else if (ctx->stage == STAGE_FORWARDUDP) {
            close_udp_remote(ctx->remote);
        }
        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

static void on_xclient_connect(uv_stream_t* stream, int status)
{
    peer_ctx_t* ctx;

    if (status < 0) {
        XLOGE("new connection error: %s.", uv_strerror(status));
        return;
    }
    ctx = xlist_alloc_back(&remote.peer_ctxs);

    uv_tcp_init(remote.loop, &ctx->io);

    ctx->io.data = ctx;
    ctx->remote = NULL;
#ifdef WITH_CLIREMOTE
    ctx->pending_ctx = NULL;
#endif
    ctx->pending_iob = NULL;
    ctx->peer_blocked = 0;
    ctx->remote_blocked = 0;
    ctx->stage = STAGE_COMMAND;
    // ctx->flag = 0;

    if (uv_accept(stream, (uv_stream_t*) &ctx->io) == 0) {
        XLOGD("proxy client connected.");
        /* enable tcp-keepalive with proxy client. */
        uv_tcp_keepalive(&ctx->io, 1, KEEPIDLE_TIME);
        uv_read_start((uv_stream_t*) &ctx->io, on_iobuf_alloc, on_peer_read);
    } else {
        XLOGE("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->io, on_peer_closed);
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp %s libuv %s, usage: %s [option]...\n", version_string(), uv_version_string(), s);
    fprintf(stderr, "[options]:\n");
#ifdef WITH_CLIREMOTE
    fprintf(stderr, "  -s <address>  server listen at. (default: 127.0.0.1:%d)\n", DEF_SERVER_PORT);
#endif
    fprintf(stderr, "  -x <address>  proxy server listen at. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
#ifdef WITH_CTRLSERVER
    fprintf(stderr, "  -r <address>  HTTP control server listen at. (default: disabled)\n");
#endif
    fprintf(stderr, "  -k <password> crypto password. (default: none)\n");
    fprintf(stderr, "  -m <method>   crypto method, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
#ifndef _WIN32
    fprintf(stderr, "  -n <number>   set max number of open files.\n");
#endif
    fprintf(stderr, "  -l <path>     write output to file. (default: write to STDOUT)\n");
    fprintf(stderr, "  -L <path>     write output to file and run as daemon. (default: write to STDOUT)\n");
    fprintf(stderr, "  -C <config>   set config file path and section. (default: trp.ini)\n");
    fprintf(stderr, "                section can be specified after colon. (default: trp.ini:server)\n");
#ifdef WITH_CLIREMOTE
    fprintf(stderr, "  -D            disable direct connect (connect TCP or UDP remote directly).\n");
#endif
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
    fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
#ifdef WITH_CLIREMOTE
    uv_tcp_t io_server;  /* server listen io */
#endif
    uv_tcp_t io_xserver; /* proxy-server listen io */
    union { struct sockaddr x; struct sockaddr_in6 d; } addr;
    union { struct sockaddr x; struct sockaddr_in6 d; } xaddr;
    char* cfg_path = NULL;
    const char* cfg_sec = "server";
#ifdef WITH_CLIREMOTE
    const char* server_str = "127.0.0.1";
#endif
    const char* xserver_str = "127.0.0.1";
#ifdef WITH_CTRLSERVER
    const char* cserver_str = NULL;
#endif
    const char* logfile = NULL;
    const char* passwd = NULL;
    int method = CRYPTO_CHACHA20;
    int daemonize = 0;
    int cfg_specified = 0;
#ifdef _WIN32
    int is_childproc = 0;
#else
    int nofile = 0;
#endif
#ifdef WITH_CLIREMOTE
    int dconnoff = 0;
#endif
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
            case 'v':  verbose = 1; continue;
#ifdef WITH_CLIREMOTE
            case 'D': dconnoff = 1; continue;
#endif
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
#ifdef WITH_CLIREMOTE
            case 's':  server_str = arg; continue;
#endif
            case 'x': xserver_str = arg; continue;
#ifdef WITH_CTRLSERVER
            case 'r': cserver_str = arg; continue;
#endif
            case 'm':      method = atoi(arg); continue;
            case 'k':      passwd = arg; continue;
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
#ifdef WITH_CLIREMOTE
            } else if (!strcmp(item->name, "D")) { dconnoff = atoi(item->value);
#endif
#ifdef WITH_CLIREMOTE
            } else if (!strcmp(item->name, "s")) { server_str = item->value;
#endif
            } else if (!strcmp(item->name, "x")) { xserver_str = item->value;
#ifdef WITH_CTRLSERVER
            } else if (!strcmp(item->name, "r")) { cserver_str = item->value;
#endif
            } else if (!strcmp(item->name, "m")) { method = atoi(item->value);
            } else if (!strcmp(item->name, "k")) { passwd = item->value;
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

    remote_private_init();
    remote.loop = uv_default_loop();

    if (passwd) {
        derive_key(remote.crypto_key, passwd);
    } else {
        XLOGI("password not set, disable crypto.");
        method = CRYPTO_NONE;
    }

    if (crypto_init(&remote.crypto, method) != 0) {
        XLOGE("invalid crypto method (%d).", method);
        goto end;
    }
    XLOGI("crypto method %d.", method);

#ifdef WITH_CLIREMOTE
    if (dconnoff) {
        XLOGI("disable direct connect.");
        remote.dconnect_off = 1;
    }
    if (parse_ip_str(server_str, DEF_SERVER_PORT, &addr.x) != 0) {
        XLOGE("invalid server address (%s).", server_str);
        goto end;
    }
#endif
    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xaddr.x) != 0) {
        XLOGE("invalid proxy server address (%s).", xserver_str);
        goto end;
    }

#ifdef WITH_CLIREMOTE
    uv_tcp_init(remote.loop, &io_server);

    error = uv_tcp_bind(&io_server, &addr.x, 0);
    if (error) {
        XLOGE("tcp bind %s failed: %s.", addr_to_str(&addr),
            uv_strerror(error));
        goto end;
    }
    error = uv_listen((uv_stream_t*) &io_server, LISTEN_BACKLOG, on_cli_remote_connect);
    if (error) {
        XLOGE("tcp listen %s failed: %s.", addr_to_str(&addr),
            uv_strerror(error));
        goto end;
    }
#endif
    uv_tcp_init(remote.loop, &io_xserver);

    error = uv_tcp_bind(&io_xserver, &xaddr.x, 0);
    if (error) {
        XLOGE("tcp bind %s failed: %s.", addr_to_str(&xaddr),
            uv_strerror(error));
        goto end;
    }
    error = uv_listen((uv_stream_t*) &io_xserver, LISTEN_BACKLOG, on_xclient_connect);
    if (error) {
        XLOGE("tcp listen %s failed: %s.", addr_to_str(&xaddr),
            uv_strerror(error));
        goto end;
    }

#ifdef WITH_CTRLSERVER
    if (cserver_str && start_ctrl_server(remote.loop, cserver_str) != 0) {
        XLOGW("start HTTP control server failed.");
        // goto end;
    }
#endif
    xlist_init(&remote.peer_ctxs, sizeof(peer_ctx_t), NULL);
    xlist_init(&remote.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);
    xlist_init(&remote.conn_reqs, sizeof(uv_connect_t), NULL);
    xlist_init(&remote.addrinfo_reqs, sizeof(uv_getaddrinfo_t), NULL);

#ifdef WITH_CLIREMOTE
    XLOGI("server listen at %s...", addr_to_str(&addr));
#endif
    XLOGI("proxy server listen at %s...", addr_to_str(&xaddr));
    uv_run(remote.loop, UV_RUN_DEFAULT);

    xlist_destroy(&remote.addrinfo_reqs);
    xlist_destroy(&remote.conn_reqs);
    xlist_destroy(&remote.io_buffers);
    xlist_destroy(&remote.peer_ctxs);
end:
    XLOGI("end of loop.");
    remote_private_destroy();
    xlog_exit();

    return 0;
}
