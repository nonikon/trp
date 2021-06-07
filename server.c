/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "common.h"
#include "xlog.h"
#include "xlist.h"
#include "xhash.h"
#include "http_server.h"

#define CLIENT_CONNECT_DELAY    (2 * 1000) /* ms */

enum {
    STAGE_INIT,
    STAGE_COMMAND,
    STAGE_CONNECT,
    STAGE_FORWARD,
};

/*  --------         --------------         --------------
 * | remote | <---> | proxy-server | <---> | proxy-client |
 *  --------        |      ^       |        --------------
 *                  |      |       |
 *  --------        |      v       |
 * | client | <---> |   server     |
 *  --------         --------------
 */

typedef struct {
    u8_t devid[DEVICE_ID_SIZE]; /* (must be the first member) */
    xlist_t clients;    /* peer_t, the clients which at COMMAND stage */
    xlist_t xclients;   /* xserver_ctx_t, the xclients which is connecting to a client */
} pending_ctx_t;

/* remote or client */
typedef struct {
    uv_tcp_t io;        /* 'io.data' pointed to 'xserver_ctx_t' */
    pending_ctx_t* dctx;/* the 'pending_ctx_t' belonging to */
} peer_t;

/* proxy-server context */
typedef struct {
    uv_tcp_t io_xclient;/* proxy-client */
    uv_timer_t timer;
    peer_t* peer;       /* remote or client */
    pending_ctx_t* dctx;/* the 'pending_ctx_t' belonging to */
    u8_t peer_is_client;
    u8_t xclient_blocked;
    u8_t peer_blocked;
    u8_t stage;
} xserver_ctx_t;

typedef struct {
    uv_write_t wreq;
    char buffer[MAX_SOCKBUF_SIZE];
} io_buf_t;

static uv_loop_t* loop;

static xhash_t pending_ctxs;    /* pending_ctx_t */
static xlist_t peers;           /* peer_t */
static xlist_t xserver_ctxs;    /* xserver_ctx_t */
static xlist_t io_buffers;      /* io_buf_t */
static xlist_t conn_reqs;       /* uv_connect_t */

static void connect_client(xserver_ctx_t* ctx, io_buf_t* iob, peer_t* client);

static void on_xclient_closed(uv_handle_t* handle);
static void on_xclient_write(uv_write_t* req, int status);
static void on_xclient_read_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf);
static void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_xclient_connect(uv_stream_t* stream, int status);

static void on_peer_read_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);

    buf->base = iob->buffer;
    buf->len = handle->data ? MAX_SOCKBUF_SIZE : sizeof(cmd_t);
}

static void on_peer_closed(uv_handle_t* handle)
{
    peer_t* peer = xcontainer_of(handle, peer_t, io);

    if (!peer->dctx) {
        xlist_erase(&peers, xlist_value_iter(peer));

        xlog_debug("current %zd peers, %zd iobufs.",
            xlist_size(&peers), xlist_size(&io_buffers));
    } else {
        xlist_erase(&peer->dctx->clients, xlist_value_iter(peer));
    }
}

static void on_peer_write(uv_write_t* req, int status)
{
    xserver_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xclient_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->peer->io) == 0) {
        xlog_debug("peer write queue cleared.");

        /* peer write queue cleared, start reading from proxy client. */
        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_xclient_read_alloc, on_xclient_read);
        ctx->xclient_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_peer_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        if (ctx != NULL) {
            /* peer is already associated with an xclient, foward data. */
            uv_buf_t wbuf;

            xlog_debug("recved %zd bytes from peer, forward.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xclient,
                &wbuf, 1, on_xclient_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_xclient) > MAX_WQUEUE_SIZE) {
                xlog_error("proxy client write queue pending.");

                /* stop reading from peer until proxy client write queue cleared. */
                uv_read_stop(stream);
                ctx->peer_blocked = 1;
            }

            /* don't release 'iob' in this place,
             *'on_xclient_write' callback will do it.
             */
            return;
        }

        /* ctx == NULL */
        {
            /* process command from client */
            cmd_t* cmd = (cmd_t*) buf->base;

            if (nread != sizeof(cmd_t) || !is_valid_cmd(cmd)
                    || !is_valid_devid(cmd->devid)) {
                xlog_warn("got an error packet from client.");
                uv_close((uv_handle_t*) stream, on_peer_closed);

            } else if (cmd->cmd == QCMD_DEVINFO) {
                peer_t* client = xcontainer_of(stream, peer_t, io);

                if (!client->dctx) {
                    pending_ctx_t* dctx = xhash_get_data(&pending_ctxs, cmd->devid);

                    xlog_debug("got DEVINFO cmd from client, process.");

                    if (dctx == XHASH_INVALID_DATA) {
                        xlog_info("device_id [%s] not exist, insert.", devid_to_str(cmd->devid));
                        /* create if not exist maybe unsafe, TODO */
                        dctx = xhash_iter_data(xhash_put_ex(
                                &pending_ctxs, cmd->devid, DEVICE_ID_SIZE));

                        xlist_init(&dctx->clients, sizeof(peer_t), NULL);
                        xlist_init(&dctx->xclients, sizeof(xserver_ctx_t), NULL);
                    }

                    if (xlist_empty(&dctx->xclients)) {
                        xlog_debug("no pending proxy client match, move to pending list.");

                        client->dctx = dctx;
                        /* move peer (client) node froms 'peers' to 'dctx->clients' */
                        xlist_paste_back(&dctx->clients,
                            xlist_cut(&peers, xlist_value_iter(client)));
                    } else {
                        xlog_debug("pending proxy client match, associate.");

                        ctx = xlist_front(&dctx->xclients);
                        ctx->dctx = NULL;
                        /* move proxy client node from 'dctx->xclients' to 'xserver_ctxs' */
                        xlist_paste_back(&xserver_ctxs, xlist_cut(
                            &dctx->xclients, xlist_value_iter(ctx)));

                        connect_client(ctx, ctx->timer.data, client);

                        uv_timer_stop(&ctx->timer);
                        uv_read_start((uv_stream_t*) &ctx->io_xclient,
                            on_xclient_read_alloc, on_xclient_read);
                    }
                }

            } else {
                xlog_warn("got an error command from client, ignore.");
                uv_close((uv_handle_t*) stream, on_peer_closed);
            }
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from peer: %s.", uv_err_name(nread));

        if (ctx != NULL) {
            uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);
        }
        uv_close((uv_handle_t*) stream, on_peer_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0.
         * just 'return' in this situation.
         */
        if (!buf->base) return;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_client_connect(uv_stream_t* stream, int status)
{
    peer_t* client;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }

    client = xlist_alloc_back(&peers);

    uv_tcp_init(loop, &client->io);

    if (uv_accept(stream, (uv_stream_t*) &client->io) == 0) {
        xlog_debug("a client connected.");

        client->io.data = NULL;
        client->dctx = NULL;

        uv_read_start((uv_stream_t*) &client->io,
            on_peer_read_alloc, on_peer_read);
    } else {
        xlog_error("uv_accept failed.");

        uv_close((uv_handle_t*) &client->io, on_peer_closed);
    }
}

static void on_remote_connected(uv_connect_t* req, int status)
{
    xserver_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_error("connect remote failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before remote connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->peer->io, on_peer_closed);
            uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);
        // }

    } else {
        xlog_debug("remote connected.");

        uv_read_start((uv_stream_t*) &ctx->peer->io,
            on_peer_read_alloc, on_peer_read);
        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_xclient_read_alloc, on_xclient_read);

        ctx->stage = STAGE_FORWARD;
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static int connect_remote(xserver_ctx_t* ctx, u8_t* addr, u16_t port)
{
    struct sockaddr_in remote_addr;
    uv_connect_t* req = xlist_alloc_back(&conn_reqs);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = port;

    memcpy(&remote_addr.sin_addr, addr, 4);
    xlog_debug("connecting remote [%s:%d]...",
        inet_ntoa(remote_addr.sin_addr), ntohs(port));

    ctx->peer = xlist_alloc_back(&peers);
    ctx->peer->io.data = ctx;
    ctx->peer->dctx = NULL;
    req->data = ctx;

    uv_tcp_init(loop, &ctx->peer->io);

    if (uv_tcp_connect(req, &ctx->peer->io,
            (struct sockaddr*) &remote_addr, on_remote_connected) != 0) {
        xlog_error("connect remote failed immediately.");

        uv_close((uv_handle_t*) &ctx->peer->io, on_peer_closed);
        xlist_erase(&conn_reqs, xlist_value_iter(req));
        return -1;
    }

    ctx->stage = STAGE_CONNECT;
    return 0;
}

static void connect_client(xserver_ctx_t* ctx, io_buf_t* iob, peer_t* client)
{
    uv_buf_t buf;

    iob->wreq.data = ctx;
    client->io.data = ctx;
    client->dctx = NULL;

    ctx->peer = client;
    ctx->peer_is_client = 1;
    ctx->stage = STAGE_FORWARD;

    buf.base = iob->buffer;
    buf.len = sizeof(cmd_t);

    uv_write(&iob->wreq, (uv_stream_t*) &client->io,
        &buf, 1, on_peer_write);
}

static void on_connect_client_timeout(uv_timer_t* timer)
{
    xserver_ctx_t* ctx = xcontainer_of(timer, xserver_ctx_t, timer);

    xlog_debug("still no available client after %d seconds.",
        CLIENT_CONNECT_DELAY / 1000);

    /* move proxy client node from 'dctx->xclients' to 'xserver_ctxs'. */
    xlist_paste_back(&xserver_ctxs, xlist_cut(
        &ctx->dctx->xclients, xlist_value_iter(ctx)));
    // ctx->dctx = NULL;

    /* free the 'iob'. */
    xlist_erase(&io_buffers, xlist_value_iter(timer->data));

    /* close this connection. */
    uv_timer_stop(timer);
    uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);
}

static void on_xclient_closed(uv_handle_t* handle)
{
    xserver_ctx_t* ctx = handle->data;

    xlist_erase(&xserver_ctxs, xlist_value_iter(ctx));
    xlog_debug("current %zd ctxs, %zd iobufs.",
        xlist_size(&xserver_ctxs), xlist_size(&io_buffers));
}

static void on_xclient_write(uv_write_t* req, int status)
{
    xserver_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->peer_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_xclient) == 0) {
        xlog_debug("proxy client write queue cleared.");

        /* proxy client write queue cleared, start reading from peer. */
        uv_read_start((uv_stream_t*) &ctx->peer->io,
            on_peer_read_alloc, on_peer_read);
        ctx->peer_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_xclient_read_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    xserver_ctx_t* ctx = handle->data;
    io_buf_t* iob = xlist_alloc_back(&io_buffers);

    buf->base = iob->buffer;
    /* set buflen 'sizeof(cmd_t)' to avoid packet splicing at command stage. */
    buf->len = ctx->stage != STAGE_COMMAND ? MAX_SOCKBUF_SIZE : sizeof(cmd_t);
}

static void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        if (ctx->stage == STAGE_FORWARD) {
            uv_buf_t wbuf;

            xlog_debug("recved %zd bytes from proxy client, forward.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->peer->io,
                &wbuf, 1, on_peer_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->peer->io) > MAX_WQUEUE_SIZE) {
                xlog_debug("peer write queue pending.");

                /* stop reading from proxy client until peer write queue cleared. */
                uv_read_stop(stream);
                ctx->xclient_blocked = 1;
            }

            /* don't release 'iob' in this place,
             * 'on_peer_write' callback will do it.
             */
            return;
        }

        if (ctx->stage == STAGE_COMMAND) {
            cmd_t* cmd = (cmd_t*) buf->base;

            if (nread != sizeof(cmd_t) || !is_valid_cmd(cmd)) {
                xlog_warn("got an error packet from proxy client.");
                uv_close((uv_handle_t*) stream, on_xclient_closed);

            } else if (cmd->cmd == QCMD_CONNECT) {
                xlog_debug("got CONNECT cmd (%s:%d) from proxy client, process.",
                    inet_ntoa(*(struct in_addr*) cmd->addr), ntohs(cmd->port));

                if (!is_valid_devid(cmd->devid)) {
                    /* device_id not set, connect remote directly. */

                    /* stop reading from proxy client until remote connected.
                     * so we can't know this connection is closed (by proxy client) or not
                     * before remote connected, TODO.
                     */
                    uv_read_stop(stream);

                    if (connect_remote(ctx, cmd->addr, cmd->port) != 0) {
                        /* connect failed immediately, just close this connection. */
                        uv_close((uv_handle_t*) stream, on_xclient_closed);
                    }

                } else {
                    /* device_id set, find an online client and send CONNECT cmd. */
                    pending_ctx_t* dctx = xhash_get_data(&pending_ctxs, cmd->devid);

                    if (dctx != XHASH_INVALID_DATA) {

                        if (!xlist_empty(&dctx->clients)) {
                            /* online client exist.
                             * send CONNECT cmd (forward the current 'iob').
                             */
                            xlog_debug("found an available client, connect to it.");
                            connect_client(ctx, iob, xlist_front(&dctx->clients));

                            /* move peer (client) node from 'dctx->clients' to 'peers' */
                            xlist_paste_back(&peers, xlist_cut_front(&dctx->clients));

                        } else {
                            /* no online client. stop reading from proxy client,
                             * and move it to 'pending_ctx_t'.
                             */
                            ctx->dctx = dctx;
                            ctx->timer.data = iob;

                            xlog_debug("no available client, pending this proxy client.");

                            uv_read_stop(stream);
                            uv_timer_init(loop, &ctx->timer);
                            uv_timer_start(&ctx->timer, on_connect_client_timeout,
                                CLIENT_CONNECT_DELAY, 0);

                            /* move proxy client node from 'xserver_ctxs' to 'dctx->xclients' */
                            xlist_paste_back(&dctx->xclients, xlist_cut(
                                &xserver_ctxs, xlist_value_iter(ctx)));
                        }

                        /* don't release 'iob' in this place,
                         * 'on_peer_write' callback will do it.
                         */
                        return;

                    } else {
                        xlog_warn("device_id not exist for proxy client.");
                        uv_close((uv_handle_t*) stream, on_xclient_closed);
                    }
                }

            } else {
                xlog_warn("got an error command from proxy client.");
                uv_close((uv_handle_t*) stream, on_xclient_closed);
            }

        } else {
            /* should not reach here */
            xlog_error("unexpected state happen.");
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from proxy client: %s, stage %d.",
            uv_err_name(nread), ctx->stage);

        if (ctx->stage == STAGE_FORWARD) {
            uv_close((uv_handle_t*) &ctx->peer->io, on_peer_closed);
        } else if (ctx->stage == STAGE_COMMAND) {
            /* do nothing */
        } else { /* STAGE_CONNECT */
            /* should not reach here */
            xlog_error("unexpected state happen when disconnect.");
        }

        uv_close((uv_handle_t*) stream, on_xclient_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0.
         * just 'return' in this situation.
         */
        if (!buf->base) return;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_xclient_connect(uv_stream_t* stream, int status)
{
    xserver_ctx_t* ctx;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }

    ctx = xlist_alloc_back(&xserver_ctxs);

    uv_tcp_init(loop, &ctx->io_xclient);

    if (uv_accept(stream, (uv_stream_t*) &ctx->io_xclient) == 0) {
        xlog_debug("a proxy client connected.");

        ctx->io_xclient.data = ctx;
        ctx->peer = NULL;
        ctx->dctx = NULL;
        ctx->peer_is_client = 0;
        ctx->xclient_blocked = 0;
        ctx->peer_blocked = 0;
        ctx->stage = STAGE_COMMAND;

        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_xclient_read_alloc, on_xclient_read);
    } else {
        xlog_error("uv_accept failed.");

        uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);
    }
}

static unsigned _pending_ctx_hash(void* v)
{
    unsigned* p = (unsigned*) ((pending_ctx_t*) v)->devid;
    unsigned  h = p[0] + p[1];

    return xhash_improve_hash(h);
}

static int _pending_ctx_equal(void* l, void* r)
{
    return !memcmp(((pending_ctx_t*) l)->devid,
                   ((pending_ctx_t*) r)->devid, DEVICE_ID_SIZE);
}

int main(int argc, char** argv)
{
    uv_tcp_t io_server;  /* server listen io */
    uv_tcp_t io_xserver; /* proxy-server listen io */
    struct sockaddr_in addr;
    struct sockaddr_in xaddr;
    const char* server_str = "127.0.0.1";
    const char* xserver_str = "127.0.0.1";
    unsigned log_level = XLOG_INFO;
    int error, i;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-s")) {
            if (++i <argc)
                server_str = argv[i];
        } else if (!strcmp(argv[i], "-x")) {
            if (++i <argc)
                xserver_str = argv[i];
        } else if (!strcmp(argv[i], "-L")) {
            if (++i < argc)
                log_level = (unsigned) atoi(argv[i]);
        } else {
            // usage, TODO
            fprintf(stderr, "wrong args.\n");
            return 1;
        }
    }

    loop = uv_default_loop();

    xlog_init(NULL);

    if (log_level <= XLOG_DEBUG) {
        xlog_ctrl(log_level, 0, 0);
    } else {
        xlog_ctrl(XLOG_INFO, 0, 0);
        xlog_warn("wrong log level, use default.");
    }

    uv_tcp_init(loop, &io_server);
    uv_tcp_init(loop, &io_xserver);

    if (parse_ip4_str(server_str, DEF_SERVER_PORT, &addr) != 0) {
        xlog_error("invalid server address [%s].", server_str);
        goto end;
    }
    if (parse_ip4_str(xserver_str, DEF_XSERVER_PORT, &xaddr) != 0) {
        xlog_error("invalid proxy server address [%s].", xserver_str);
        goto end;
    }

    uv_tcp_bind(&io_server, (struct sockaddr*) &addr, 0);
    uv_tcp_bind(&io_xserver, (struct sockaddr*) &xaddr, 0);

    error = uv_listen((uv_stream_t*) &io_server,
                LISTEN_BACKLOG, on_client_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", server_str,
            uv_strerror(error));
        goto end;
    }

    error = uv_listen((uv_stream_t*) &io_xserver,
                LISTEN_BACKLOG, on_xclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.", xserver_str,
            uv_strerror(error));
        goto end;
    }

    // http_server_start(loop, "0.0.0.0", 8888); // TODO

    xhash_init(&pending_ctxs, -1, sizeof(pending_ctx_t),
        _pending_ctx_hash, _pending_ctx_equal, NULL);
    xlist_init(&peers, sizeof(peer_t), NULL);
    xlist_init(&xserver_ctxs, sizeof(xserver_ctx_t), NULL);
    xlist_init(&io_buffers, sizeof(io_buf_t), NULL);
    xlist_init(&conn_reqs, sizeof(uv_connect_t), NULL);

    xlog_info("server listen at [%s:%d]...",
        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    xlog_info("proxy server listen at [%s:%d]...",
        inet_ntoa(xaddr.sin_addr), ntohs(xaddr.sin_port));
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&conn_reqs);
    xlist_destroy(&io_buffers);
    xlist_destroy(&xserver_ctxs);
    xlist_destroy(&peers);
    xhash_destroy(&pending_ctxs);
end:
    xlog_info("end of loop.");
    uv_close((uv_handle_t*) &io_server, NULL);
    uv_close((uv_handle_t*) &io_xserver, NULL);
    xlog_exit();

    return 0;
}
