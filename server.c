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
            xlog_debug("%zd bytes from proxy client, to client.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->remote;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->remote->c.io,
                &wbuf, 1, on_cli_remote_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->remote->c.io) > MAX_WQUEUE_SIZE) {
                xlog_debug("client write queue pending.");

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
            xlog_debug("%zd bytes from proxy client, to tcp remote.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->remote;

            remote.crypto.decrypt(&ctx->edctx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->remote->t.io,
                &wbuf, 1, on_tcp_remote_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->remote->t.io) > MAX_WQUEUE_SIZE) {
                xlog_debug("remote write queue pending.");

                /* stop reading from peer until remote write queue cleared. */
                uv_read_stop(stream);
                ctx->peer_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }

        if (ctx->stage == STAGE_FORWARDUDP) {
            xlog_debug("%zd udp bytes from proxy client.", nread);

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
        xlog_error("unexpected state happen.");
        return;
    }

    if (nread < 0) {
        xlog_debug("disconnected from proxy client: %s, stage %d.",
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
        xlog_error("new connection error: %s.", uv_strerror(status));
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

    if (uv_accept(stream, (uv_stream_t*) &ctx->io) == 0) {
        xlog_debug("proxy client connected.");
        /* enable tcp-keepalive with proxy client. */
        uv_tcp_keepalive(&ctx->io, 1, KEEPIDLE_TIME);
        uv_read_start((uv_stream_t*) &ctx->io, on_iobuf_alloc, on_peer_read);
    } else {
        xlog_error("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->io, on_peer_closed);
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp %d.%d.%d, libuv %s, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, uv_version_string(), s);
    fprintf(stderr, "[options]:\n");
#ifdef WITH_CLIREMOTE
    fprintf(stderr, "  -s <address>  server listen at. (default: 127.0.0.1:%d)\n", DEF_SERVER_PORT);
#endif
    fprintf(stderr, "  -x <address>  proxy server listen at. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -c <address>  control server listen at. (default: disabled)\n");
    fprintf(stderr, "  -k <password> crypto password. (default: none)\n");
    fprintf(stderr, "  -m <method>   crypto method, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
#ifdef _WIN32
    fprintf(stderr, "  -L <path>     write output to file. (default: write to STDOUT)\n");
#else
    fprintf(stderr, "  -n <number>   set max number of open files.\n");
    fprintf(stderr, "  -L <path>     write output to file and run as daemon. (default: write to STDOUT)\n");
#endif
#ifdef WITH_CLIREMOTE
    fprintf(stderr, "  -D            disable direct connect (connect tcp or udp remote directly).\n");
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
#ifdef WITH_CLIREMOTE
    const char* server_str = "127.0.0.1";
#endif
    const char* xserver_str = "127.0.0.1";
    const char* logfile = NULL;
    const char* passwd = NULL;
    int method = CRYPTO_CHACHA20;
#ifndef _WIN32
    int nofile = 0;
#endif
#ifdef WITH_CLIREMOTE
    int dconnoff = 0;
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
        case 'v':  verbose = 1; continue;
#ifdef WITH_CLIREMOTE
        case 'D': dconnoff = 1; continue;
#endif
        case 'h':
            usage(argv[0]);
            return 1;
        }

        arg = argv[i][2] ? argv[i] + 2 : (++i < argc ? argv[i] : NULL);

        if (arg) switch (opt) {
#ifdef WITH_CLIREMOTE
        case 's':  server_str = arg; continue;
#endif
        case 'x': xserver_str = arg; continue;
        case 'm':      method = atoi(arg); continue;
        case 'k':      passwd = arg; continue;
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

    remote_private_init();
    remote.loop = uv_default_loop();

    if (passwd) {
        derive_key(remote.crypto_key, passwd);
    } else {
        xlog_info("password not set, disable crypto.");
        method = CRYPTO_NONE;
    }

    if (crypto_init(&remote.crypto, method) != 0) {
        xlog_error("invalid crypto method: %d.", method);
        goto end;
    }

#ifdef WITH_CLIREMOTE
    if (dconnoff) {
        xlog_info("disable direct connect.");
        remote.dconnect_off = 1;
    }
    if (parse_ip_str(server_str, DEF_SERVER_PORT, &addr.x) != 0) {
        xlog_error("invalid server address [%s].", server_str);
        goto end;
    }
#endif
    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xaddr.x) != 0) {
        xlog_error("invalid proxy server address [%s].", xserver_str);
        goto end;
    }

#ifdef WITH_CLIREMOTE
    uv_tcp_init(remote.loop, &io_server);
    uv_tcp_bind(&io_server, &addr.x, 0);

    error = uv_listen((uv_stream_t*) &io_server, LISTEN_BACKLOG, on_cli_remote_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", addr_to_str(&addr), uv_strerror(error));
        goto end;
    }
#endif
    uv_tcp_init(remote.loop, &io_xserver);
    uv_tcp_bind(&io_xserver, &xaddr.x, 0);

    error = uv_listen((uv_stream_t*) &io_xserver, LISTEN_BACKLOG, on_xclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", addr_to_str(&xaddr), uv_strerror(error));
        goto end;
    }

    // http_server_start(loop, "127.0.0.1"); // TODO

    xlist_init(&remote.peer_ctxs, sizeof(peer_ctx_t), NULL);
    xlist_init(&remote.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);
    xlist_init(&remote.conn_reqs, sizeof(uv_connect_t), NULL);
    xlist_init(&remote.addrinfo_reqs, sizeof(uv_getaddrinfo_t), NULL);

#ifdef WITH_CLIREMOTE
    xlog_info("server listen at [%s]...", addr_to_str(&addr));
#endif
    xlog_info("proxy server listen at [%s]...", addr_to_str(&xaddr));
    uv_run(remote.loop, UV_RUN_DEFAULT);

    xlist_destroy(&remote.addrinfo_reqs);
    xlist_destroy(&remote.conn_reqs);
    xlist_destroy(&remote.io_buffers);
    xlist_destroy(&remote.peer_ctxs);
end:
    xlog_info("end of loop.");
    remote_private_destroy();
    xlog_exit();

    return 0;
}
