/*
 * Copyright (C) 2021-2023 nonikon@qq.com.
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

/*  --------         --------         --------
 * | remote | <---> | client | <---> | server |
 *  --------         --------         --------
 */

static uv_timer_t reconnect_timer;

static union { struct sockaddr x; struct sockaddr_dm  d; } server_addr;
static union { struct sockaddr x; struct sockaddr_in6 d; } server_addr_r; /* store resolved server domain */

static crypto_t crypto;     /* crypto between client and server */
static u8_t crypto_key[16]; /* crypto key between client and server */
static u8_t device_id[DEVICE_ID_SIZE];

static int nconnect = 1;

static void on_server_connected(uv_connect_t* req, int status);
static void new_server_connection(uv_timer_t* handle);

/* override */ void on_peer_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    peer_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        if (ctx->stage == STAGE_FORWARDTCP) {
            uv_buf_t wbuf;
            xlog_debug("%zd bytes from server, to tcp remote.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->remote;

            remote.crypto.decrypt(&ctx->edctx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->remote->t.io,
                &wbuf, 1, on_tcp_remote_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->remote->t.io) > MAX_WQUEUE_SIZE) {
                xlog_debug("remote write queue pending.");

                /* stop reading from server until remote write queue cleared. */
                uv_read_stop(stream);
                ctx->peer_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }

        if (ctx->stage == STAGE_FORWARDUDP) {
            xlog_debug("%zd udp bytes from server.", nread);

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

            ++nconnect;
            /* start a new server connection always. */
            new_server_connection(NULL);

            if (invoke_encrypted_peer_command(ctx, iob) != 0) {
                uv_close((uv_handle_t*) stream, on_peer_closed);
            }
            /* 'iob' free later. */
            return;
        }

        /* should not reach here */
        xlog_error("unexpected state happen when read.");
        return;
    }

    if (nread < 0) {
        xlog_debug("disconnected from server: %s, stage %d.",
            uv_err_name((int) nread), ctx->stage);

        uv_close((uv_handle_t*) stream, on_peer_closed);

        if (ctx->stage == STAGE_COMMAND) {
            xlog_warn("connection closed by server at COMMAND stage.");
            ++nconnect;
            if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
                /* reconnect after RECONNECT_SRV_INTVL seconds. */
                uv_timer_start(&reconnect_timer, new_server_connection,
                    RECONNECT_SRV_INTVL * 1000, 0);
            }
        } else if (ctx->stage == STAGE_FORWARDTCP) {
            uv_close((uv_handle_t*) &ctx->remote->t.io, on_tcp_remote_closed);
        } else if (ctx->stage == STAGE_FORWARDUDP) {
            close_udp_remote(ctx->remote);
        }
        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

static void report_device_id(peer_ctx_t* ctx)
{
    io_buf_t* iob = xlist_alloc_back(&remote.io_buffers);
    cmd_t* cmd = (cmd_t*) (iob->buffer + MAX_NONCE_LEN);
    uv_buf_t wbuf;

    iob->wreq.data = ctx;

    wbuf.base = iob->buffer;
    wbuf.len = CMD_MAX_SIZE + MAX_NONCE_LEN;

    /* generate and prepend iv in the first packet */
    generate_nonce((u8_t*) iob->buffer);

    cmd->tag = CMD_TAG;
    cmd->major = VERSION_MAJOR;
    cmd->minor = VERSION_MINOR;
    cmd->cmd = CMD_REPORT_DEVID;
    cmd->len = DEVICE_ID_SIZE;

    memcpy(cmd->data, device_id, DEVICE_ID_SIZE);

    fill_command_md(cmd);
    /* use 'ctx->edctx' temporarily. */
    crypto.init(&ctx->edctx, crypto_key, (u8_t*) iob->buffer);
    crypto.encrypt(&ctx->edctx, (u8_t*) cmd, CMD_MAX_SIZE);

    uv_write(&iob->wreq, (uv_stream_t*) &ctx->io, &wbuf, 1, on_peer_write);
}

static void on_server_connected(uv_connect_t* req, int status)
{
    static int retry_displayed = 1;
    peer_ctx_t* ctx = req->data;

    if (status < 0) {
        uv_close((uv_handle_t*) &ctx->io, on_peer_closed);

        /* mark server domain need to be resolved again. */
        server_addr_r.x.sa_family = 0;
        ++nconnect;
        if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
            /* reconnect after RECONNECT_SRV_INTVL seconds. */
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_SRV_INTVL * 1000, 0);
        }
        if (retry_displayed) {
            xlog_debug("connect server failed: %s, retry every %d seconds.",
                uv_err_name(status), RECONNECT_SRV_INTVL);
        } else {
            xlog_error("connect server failed: %s, retry every %d seconds.",
                uv_err_name(status), RECONNECT_SRV_INTVL);
            retry_displayed = 1;
        }
    } else {
        /* enable tcp-keepalive. */
        uv_tcp_keepalive(&ctx->io, 1, KEEPIDLE_TIME);
        uv_read_start((uv_stream_t*) &ctx->io, on_iobuf_alloc, on_peer_read);

        report_device_id(ctx);

        ctx->stage = STAGE_COMMAND;

        if (!retry_displayed) {
            xlog_debug("server connected.");
        } else {
            xlog_info("server connected.");
            retry_displayed = 0;
        }
        if (nconnect > 0 && !uv_is_active((uv_handle_t*) &reconnect_timer)) {
            new_server_connection(NULL);
        }
    }

    xlist_erase(&remote.conn_reqs, xlist_value_iter(req));
}

static void connect_server(struct sockaddr* addr)
{
    peer_ctx_t* ctx = xlist_alloc_back(&remote.peer_ctxs);
    uv_connect_t* req = xlist_alloc_back(&remote.conn_reqs);

    uv_tcp_init(remote.loop, &ctx->io);

    ctx->io.data = ctx;
    ctx->remote = NULL;
    // ctx->pending_ctx = NULL;
    ctx->pending_iob = NULL;
    ctx->peer_blocked = 0;
    ctx->remote_blocked = 0;
    ctx->stage = STAGE_INIT;

    req->data = ctx;

    xlog_debug("connecting server [%s]...", addr_to_str(addr));

    if (uv_tcp_connect(req, &ctx->io, addr, on_server_connected) != 0) {
        xlog_error("connect server failed immediately.");

        ++nconnect;
        if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
            /* reconnect after RECONNECT_SRV_INTVL seconds. */
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_SRV_INTVL * 1000, 0);
        }

        uv_close((uv_handle_t*) &ctx->io, on_peer_closed);
        xlist_erase(&remote.conn_reqs, xlist_value_iter(req));
    }
}

static void on_server_domain_resolved(
        uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    static int retry_displayed = 1;

    if (status < 0) {
        if (retry_displayed) {
            xlog_debug("resolve server domain failed: %s, retry every %d seconds.",
                uv_err_name(status), RECONNECT_SRV_INTVL);
        } else {
            xlog_error("resolve server domain failed: %s, retry every %d seconds.",
                uv_err_name(status), RECONNECT_SRV_INTVL);
            retry_displayed = 1;
        }
        ++nconnect;
        if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
            /* reconnect after RECONNECT_SRV_INTVL seconds. */
            uv_timer_start(&reconnect_timer, new_server_connection,
                RECONNECT_SRV_INTVL * 1000, 0);
        }

    } else {
        if (!retry_displayed) {
            xlog_debug("resolve server domain result [%s], connecting...",
                addr_to_str(res->ai_addr));
        } else {
            xlog_info("resolve server domain result [%s], connecting...",
                addr_to_str(res->ai_addr));
            retry_displayed = 0;
        }

        /* save resolved server domain. */
        memcpy(&server_addr_r, res->ai_addr, res->ai_addrlen);

        connect_server(res->ai_addr);
        uv_freeaddrinfo(res);
    }

    xlist_erase(&remote.addrinfo_reqs, xlist_value_iter(req));
}

static void new_server_connection(uv_timer_t* timer)
{
    --nconnect;

    if (server_addr.x.sa_family) {
        /* server address is ipv4/ipv6, connect it directly. */
        connect_server(&server_addr.x);

    } else if (server_addr_r.x.sa_family) {
        /* use cached resolve result. */
        connect_server(&server_addr_r.x);

    } else {
        /* server address is domain, resolve it. */
        struct addrinfo hints;
        char portstr[8];
        uv_getaddrinfo_t* req = xlist_alloc_back(&remote.addrinfo_reqs);

        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_UNSPEC; /* ipv4 and ipv6 */
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = 0;

        sprintf(portstr, "%d", ntohs(server_addr.d.sdm_port));

        if (uv_getaddrinfo(remote.loop, req, on_server_domain_resolved,
                server_addr.d.sdm_addr, portstr, &hints) != 0) {
            xlog_error("uv_getaddrinfo (%s) failed immediately.", server_addr.d.sdm_addr);

            ++nconnect;
            if (!uv_is_active((uv_handle_t*) &reconnect_timer)) {
                /* reconnect after RECONNECT_SRV_INTVL seconds.
                 * 'reconnect_timer' is inactive when 'new_server_connection'
                 * is invoked by 'reconnect_timer'. so,
                 * 'uv_timer_start' will not be called twice anyway.
                 */
                uv_timer_start(&reconnect_timer, new_server_connection,
                    RECONNECT_SRV_INTVL * 1000, 0);
            }

            xlist_erase(&remote.addrinfo_reqs, xlist_value_iter(req));
        }
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp %s libuv %s, usage: %s [option]...\n", version_string(), uv_version_string(), s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -s <address>  server connect to. (default: 127.0.0.1:%d)\n", DEF_SERVER_PORT);
#ifdef WITH_CTRLSERVER
    fprintf(stderr, "  -r <address>  HTTP control server listen at. (default: disabled)\n");
#endif
    fprintf(stderr, "  -d <devid>    device id (1~16 bytes string) of this client. (default: %s)\n", DEF_DEVID_STRING);
    fprintf(stderr, "  -k <password> crypto password with server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> crypto password with proxy client. (default: none)\n");
    fprintf(stderr, "  -m <method>   crypto method with server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   crypto method with proxy client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -c <number>   set the number of connection pools. (default: 1)\n");
#ifndef _WIN32
    fprintf(stderr, "  -n <number>   set max number of open files.\n");
#endif
    fprintf(stderr, "  -L <path>     write output to file and run as daemon. (default: write to STDOUT)\n");
    fprintf(stderr, "  -C <path>     set config file path. (default: trp.ini)\n");
    fprintf(stderr, "  -S <section>  set config section name. (default: client)\n");
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
    const char* cfg_path = DEF_CONFIG_FILE;
    const char* cfg_sec = "client";
    const char* server_str = "127.0.0.1";
#ifdef WITH_CTRLSERVER
    const char* cserver_str = NULL;
#endif
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
#ifdef _WIN32
    int is_childproc = 0;
#else
    int nofile = 0;
#endif
    int verbose = 0;
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
            case 's':  server_str = arg; continue;
#ifdef WITH_CTRLSERVER
            case 'r': cserver_str = arg; continue;
#endif
            case 'd':   devid_str = arg; continue;
            case 'm':      method = atoi(arg); continue;
            case 'M':     methodx = atoi(arg); continue;
            case 'k':      passwd = arg; continue;
            case 'K':     passwdx = arg; continue;
            case 'c':    nconnect = atoi(arg); continue;
#ifndef _WIN32
            case 'n':      nofile = atoi(arg); continue;
#endif
            case 'L':     logfile = arg; continue;
            case 'C':    cfg_path = arg; continue;
            case 'S':     cfg_sec = arg; continue;
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

    if (load_config_file(cfg_path, cfg_sec) != 0) {
        fprintf(stderr, "error when parse config file [%s], ignore configs.\n", cfg_path);
    } else {
        config_item_t* i = NULL;

        while (!!(i = get_config_item(i))) {
            if (!i->name[0] || !i->value[0]) {
                fprintf(stderr, "invalid config item [%s=%s], ignore.\n", i->name, i->value);
            } else if (!strcmp(i->name, "v")) {
                verbose = atoi(i->value);
            } else if (!strcmp(i->name, "s")) {
                server_str = i->value;
#ifdef WITH_CTRLSERVER
            } else if (!strcmp(i->name, "r")) {
                cserver_str = i->value;
#endif
            } else if (!strcmp(i->name, "d")) {
                devid_str = i->value;
            } else if (!strcmp(i->name, "m")) {
                method = atoi(i->value);
            } else if (!strcmp(i->name, "M")) {
                methodx = atoi(i->value);
            } else if (!strcmp(i->name, "k")) {
                passwd = i->value;
            } else if (!strcmp(i->name, "K")) {
                passwdx = i->value;
            } else if (!strcmp(i->name, "c")) {
                nconnect = atoi(i->value);
#ifndef _WIN32
            } else if (!strcmp(i->name, "n")) {
                nofile = atoi(i->value);
#endif
            } else if (!strcmp(i->name, "L")) {
                logfile = i->value;
            } else {
                fprintf(stderr, "invalid config item name [%s], ignore.\n", i->name);
            }
        }
    }

    if (xlog_init(logfile) != 0) {
        fprintf(stderr, "open logfile failed.\n");
    }

    if (!verbose) {
        xlog_ctrl(XLOG_INFO, 0, 0);
    } else {
        xlog_info("enable verbose output.");
    }

#ifdef _WIN32
    if (logfile && !is_childproc) {
        xlog_exit(logfile); /* close log file */
        if (daemon(argc, argv) != 0) {
            xlog_init(logfile); /* reopen log file when daemon failed */
            xlog_error("run as daemon failed: %u", GetLastError());
        }
    }
#else
    if (logfile) {
        xlog_exit(logfile);
        if (daemon(1, 0) != 0) {
            xlog_init(logfile);
            xlog_error("run as daemon failed: %s.", strerror(errno));
        }
    }
    signal(SIGPIPE, SIG_IGN);

    if (nofile > 1024) {
        struct rlimit limit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            xlog_warn("set NOFILE limit to [%d] failed: %s.", nofile, strerror(errno));
        } else {
            xlog_info("set NOFILE limit to [%d].", nofile);
        }
    }
#endif
    seed_rand((u32_t) time(NULL));

    remote_private_init();
    remote.loop = uv_default_loop();

    if (nconnect <= 0 || nconnect > 1024) {
        xlog_warn("invalid connection pool size [%d], reset to [1].", nconnect);
        nconnect = 1;
    }

    if (!devid_str) {
        xlog_info("device id not set, use default.");
        devid_str = DEF_DEVID_STRING;
    }
    if (str_to_devid(device_id, devid_str) != 0) {
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
        derive_key(remote.crypto_key, passwdx);
    } else {
        xlog_info("PASSWORD (-K) not set, disable crypto with proxy client.");
        methodx = CRYPTO_NONE;
    }

    if (crypto_init(&crypto, method) != 0) {
        xlog_error("invalid crypto method: [%d].", method);
        goto end;
    }
    if (crypto_init(&remote.crypto, methodx) != 0) {
        xlog_error("invalid crypto METHOD: [%d].", methodx);
        goto end;
    }
    xlog_info("crypto method [%d], METHOD [%d].", method, methodx);

    if (parse_ip_str(server_str, DEF_SERVER_PORT, &server_addr.x) != 0
            && parse_domain_str(server_str, DEF_SERVER_PORT, &server_addr.d) != 0) {
        xlog_error("invalid server address [%s].", server_str);
        goto end;
    }

#ifdef WITH_CTRLSERVER
    if (cserver_str && start_ctrl_server(remote.loop, cserver_str) != 0) {
        xlog_warn("start HTTP control server failed.");
        // goto end;
    }
#endif
    xlist_init(&remote.peer_ctxs, sizeof(peer_ctx_t), NULL);
    xlist_init(&remote.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);
    xlist_init(&remote.conn_reqs, sizeof(uv_connect_t), NULL);
    xlist_init(&remote.addrinfo_reqs, sizeof(uv_getaddrinfo_t), NULL);

    uv_timer_init(remote.loop, &reconnect_timer);

    xlog_info("device id [%s].", devid_to_str(device_id));
    xlog_info("server address [%s], connecting...", addr_to_str(&server_addr));
    new_server_connection(NULL);
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