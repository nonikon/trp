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

#include "common.h"
#include "xlog.h"
#include "xlist.h"
#include "xhash.h"
#include "crypto.h"

#define CONNECT_CLIENT_TIMEOUT  (10 * 1000) /* ms */
#define KEEPIDLE_TIME           (35) /* s */

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
    uv_timer_t timer;   /* xclients connect timeout timer */
} pending_ctx_t;

/* remote or client */
typedef struct {
    uv_tcp_t io;                /* 'io.data' pointed to 'xserver_ctx_t' */
    pending_ctx_t* pending_ctx; /* the 'pending_ctx_t' belonging to */
    crypto_ctx_t edctx;         /* 'dctx' at COMMAND stage, 'ectx' at FORWARD stage */
} peer_t;

/* proxy-server context */
typedef struct {
    uv_tcp_t io_xclient;        /* proxy-client */
    peer_t* peer;               /* remote or client */
    pending_ctx_t* pending_ctx; /* the 'pending_ctx_t' belonging to */
    io_buf_t* pending_iob;      /* the pending 'io_buf_t' before 'remote' connected */
    crypto_ctx_t dctx;
    u8_t peer_is_client;
    u8_t xclient_blocked;
    u8_t peer_blocked;
    u8_t stage;
} xserver_ctx_t;

static uv_loop_t* loop;

static xhash_t pending_ctxs;    /* pending_ctx_t */
static xlist_t peers;           /* peer_t */
static xlist_t xserver_ctxs;    /* xserver_ctx_t */
static xlist_t io_buffers;      /* io_buf_t */
static xlist_t conn_reqs;       /* uv_connect_t */
static xlist_t addrinfo_reqs;   /* uv_getaddrinfo_t */

static crypto_t crypto;
static u8_t crypto_key[16];

static void connect_client(xserver_ctx_t* ctx, peer_t* client);

static void on_xclient_closed(uv_handle_t* handle);
static void on_xclient_write(uv_write_t* req, int status);
static void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_xclient_connect(uv_stream_t* stream, int status);

static void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&io_buffers);

    buf->base = iob->buffer;
    buf->len = MAX_SOCKBUF_SIZE;
}

static void on_peer_closed(uv_handle_t* handle)
{
    peer_t* peer = xcontainer_of(handle, peer_t, io);

    if (!peer->pending_ctx) {
        xlist_erase(&peers, xlist_value_iter(peer));

        xlog_debug("current %zd peers, %zd iobufs.",
            xlist_size(&peers), xlist_size(&io_buffers));
    } else {
        xlist_erase(&peer->pending_ctx->clients, xlist_value_iter(peer));

        xlog_debug("current %zd pending clients with this devid, %zd iobufs.",
            xlist_size(&peer->pending_ctx->clients), xlist_size(&io_buffers));
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
            on_iobuf_alloc, on_xclient_read);
        ctx->xclient_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
}

static void on_client_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        if (ctx != NULL) {
            /* client is already associated with an xclient, foward data. */
            uv_buf_t wbuf;

            xlog_debug("recved %zd bytes from client, forward.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xclient,
                &wbuf, 1, on_xclient_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_xclient) > MAX_WQUEUE_SIZE) {
                xlog_debug("proxy client write queue pending.");

                /* stop reading from client until proxy client write queue cleared. */
                uv_read_stop(stream);
                ctx->peer_blocked = 1;
            }

            /* don't release 'iob' in this place,
             *'on_xclient_write' callback will do it.
             */
            return;
        }

        /* ctx == NULL */
        if (nread == CMD_MAX_SIZE + MAX_NONCE_LEN) {
            /* process command from client */
            cmd_t* cmd = (cmd_t*) (buf->base + MAX_NONCE_LEN);
            peer_t* client = xcontainer_of(stream, peer_t, io);

            crypto.init(&client->edctx, crypto_key, (u8_t*) buf->base);
            crypto.decrypt(&client->edctx, (u8_t*) cmd, (u32_t) (nread - MAX_NONCE_LEN));

            if (!is_valid_cmd(cmd)) {
                xlog_warn("got an error packet (content) from client.");
                uv_close((uv_handle_t*) stream, on_peer_closed);

            } else if (cmd->cmd == CMD_REPORT_DEVID) {

                if (is_valid_devid(cmd->data) && !client->pending_ctx) {
                    pending_ctx_t* pdctx = xhash_get_data(&pending_ctxs, cmd->data);

                    xlog_debug("got REPORT_DEVID (%s) cmd from client, process.",
                        devid_to_str(cmd->data));

                    if (pdctx == XHASH_INVALID_DATA) {
                        xlog_info("device_id [%s] not exist, insert.", devid_to_str(cmd->data));

                        /* create if not exist maybe unsafe, TODO */
                        pdctx = xhash_iter_data(xhash_put_ex(&pending_ctxs,
                                    cmd->data, DEVICE_ID_SIZE));

                        xlist_init(&pdctx->clients, sizeof(peer_t), NULL);
                        xlist_init(&pdctx->xclients, sizeof(xserver_ctx_t), NULL);

                        uv_timer_init(loop, &pdctx->timer);
                    }

                    if (xlist_empty(&pdctx->xclients)) {
                        xlog_debug("no pending proxy client match, move to pending list.");

                        client->pending_ctx = pdctx;
                        /* move peer (client) node froms 'peers' to 'pdctx->clients' */
                        xlist_paste_back(&pdctx->clients,
                            xlist_cut(&peers, xlist_value_iter(client)));

                    } else {
                        xlog_debug("pending proxy client match, associate.");

                        ctx = xlist_front(&pdctx->xclients);
                        ctx->pending_ctx = NULL;
                        /* move proxy client node from 'pdctx->xclients' to 'xserver_ctxs' */
                        xlist_paste_back(&xserver_ctxs,
                            xlist_cut(&pdctx->xclients, xlist_value_iter(ctx)));

                        uv_read_start((uv_stream_t*) &ctx->io_xclient,
                            on_iobuf_alloc, on_xclient_read);

                        if (!xlist_empty(&pdctx->xclients)) {
                            /* still have some pending xclients, reset timer. */
                            uv_timer_again(&pdctx->timer);
                        } else {
                            /* no pending xclient exist, stop timer. */
                            uv_timer_stop(&pdctx->timer);
                        }

                        connect_client(ctx, client);
                    }
                } else {
                    xlog_warn("invalid device id from client, ignore.");
                }

            } else {
                xlog_warn("got an error command (%d) from client.", cmd->cmd);
                uv_close((uv_handle_t*) stream, on_peer_closed);
            }

        } else {
            xlog_warn("got an error packet (length) from client.");
            uv_close((uv_handle_t*) stream, on_peer_closed);
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from peer: %s.", uv_err_name((int) nread));

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

    client->io.data = NULL;
    client->pending_ctx = NULL;

    if (uv_accept(stream, (uv_stream_t*) &client->io) == 0) {
        xlog_debug("a client connected.");

        uv_read_start((uv_stream_t*) &client->io,
            on_iobuf_alloc, on_client_read);
        /* enable tcp-keepalive with client. */
        uv_tcp_keepalive(&client->io, 1, KEEPIDLE_TIME);
    } else {
        xlog_error("uv_accept failed.");

        uv_close((uv_handle_t*) &client->io, on_peer_closed);
    }
}

static void on_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xserver_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from remote, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        crypto.encrypt(&ctx->peer->edctx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xclient,
            &wbuf, 1, on_xclient_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_xclient) > MAX_WQUEUE_SIZE) {
            xlog_debug("proxy client write queue pending.");

            /* stop reading from remote until proxy client write queue cleared. */
            uv_read_stop(stream);
            ctx->peer_blocked = 1;
        }

        /* 'iob' free later. */
    } else if (nread < 0) {
        xlog_debug("disconnected from remote: %s.", uv_err_name((int) nread));

        uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);
        uv_close((uv_handle_t*) stream, on_peer_closed);

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
        io_buf_t* iob = ctx->pending_iob;

        xlog_debug("remote connected.");

        convert_nonce((u8_t*) iob->buffer);
        crypto.init(&ctx->peer->edctx, crypto_key, (u8_t*) iob->buffer);

        if (iob->len > 0) {
            uv_buf_t wbuf;

            wbuf.base = iob->buffer + iob->idx;
            wbuf.len = iob->len;

            iob->wreq.data = ctx;

            crypto.decrypt(&ctx->dctx, (u8_t*) wbuf.base, wbuf.len);
            /* write 'iob' to remote, 'iob' free later. */
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->peer->io,
                &wbuf, 1, on_peer_write);
        } else {
            /* free this 'iob' now. */
            xlist_erase(&io_buffers, xlist_value_iter(iob));
        }

        uv_read_start((uv_stream_t*) &ctx->peer->io,
            on_iobuf_alloc, on_remote_read);
        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_iobuf_alloc, on_xclient_read);

        ctx->pending_iob = NULL;
        ctx->stage = STAGE_FORWARD;
    }

    xlist_erase(&conn_reqs, xlist_value_iter(req));
}

static int connect_remote(xserver_ctx_t* ctx, struct sockaddr* addr)
{
    uv_connect_t* req = xlist_alloc_back(&conn_reqs);

    ctx->peer = xlist_alloc_back(&peers);
    ctx->peer->io.data = ctx;
    ctx->peer->pending_ctx = NULL;
    req->data = ctx;

    uv_tcp_init(loop, &ctx->peer->io);

    if (uv_tcp_connect(req, &ctx->peer->io, addr, on_remote_connected) != 0) {
        xlog_error("connect remote failed immediately.");

        uv_close((uv_handle_t*) &ctx->peer->io, on_peer_closed);
        xlist_erase(&conn_reqs, xlist_value_iter(req));
        return -1;
    }

    ctx->stage = STAGE_CONNECT;
    return 0;
}

static void on_domain_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    xserver_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_debug("resolve domain failed: %s.", uv_err_name(status));
        uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);

    } else {
        xlog_debug("resolve result [%s], connect it.", addr_to_str(res->ai_addr));

        if (connect_remote(ctx, res->ai_addr) != 0) {
            /* connect failed immediately, just close this connection. */
            uv_close((uv_handle_t*) &ctx->io_xclient, on_xclient_closed);
        }
        uv_freeaddrinfo(res);
    }

    xlist_erase(&addrinfo_reqs, xlist_value_iter(req));
}

static void connect_client(xserver_ctx_t* ctx, peer_t* client)
{
    io_buf_t* iob = ctx->pending_iob;

    client->io.data = ctx;
    client->pending_ctx = NULL;

    ctx->peer = client;
    ctx->peer_is_client = 1;
    ctx->pending_iob = NULL;
    ctx->stage = STAGE_FORWARD;

    if (iob->len > 0) {
        uv_buf_t wbuf;

        wbuf.base = iob->buffer + iob->idx;
        wbuf.len = iob->len;

        iob->wreq.data = ctx;
        /* write this 'iob' to client, 'iob' free later. */
        uv_write(&iob->wreq, (uv_stream_t*) &client->io,
            &wbuf, 1, on_peer_write);
    } else {
        /* free this 'iob' now. */
        xlist_erase(&io_buffers, xlist_value_iter(iob));
    }

    /* disable tcp-keepalive with client. */
    // uv_tcp_keepalive(&client->io, 0, 0);
}

static void on_connect_client_timeout(uv_timer_t* timer)
{
    pending_ctx_t* ctx = xcontainer_of(timer, pending_ctx_t, timer);

    xlog_debug("still no available client after %d seconds, close %zd pending xclient(s).",
        CONNECT_CLIENT_TIMEOUT / 1000, xlist_size(&ctx->xclients));

    do {
        xserver_ctx_t* x = xlist_cut_front(&ctx->xclients);

        /* move this proxy client node from 'ctx->xclients' to 'xserver_ctxs'. */
        xlist_paste_back(&xserver_ctxs, x);
        /* close this proxy client. */
        uv_close((uv_handle_t*) &x->io_xclient, on_xclient_closed);
    }
    while (!xlist_empty(&ctx->xclients));

    /* timer is already stopped. */
    // uv_timer_stop(timer);
}

static void on_xclient_closed(uv_handle_t* handle)
{
    xserver_ctx_t* ctx = handle->data;

    if (ctx->pending_iob) {
        xlist_erase(&io_buffers, xlist_value_iter(ctx->pending_iob));
    }
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
        uv_read_start((uv_stream_t*) &ctx->peer->io, on_iobuf_alloc,
            ctx->peer_is_client ? on_client_read : on_remote_read);
        ctx->peer_blocked = 0;
    }

    xlist_erase(&io_buffers, xlist_value_iter(iob));
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

            if (!ctx->peer_is_client) {
                crypto.decrypt(&ctx->dctx, (u8_t*) wbuf.base, wbuf.len);
            }

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

            if (nread >= CMD_MAX_SIZE + MAX_NONCE_LEN) {
                cmd_t* cmd = (cmd_t*) (buf->base + MAX_NONCE_LEN);

                crypto.init(&ctx->dctx, crypto_key, (u8_t*) buf->base);
                crypto.decrypt(&ctx->dctx, (u8_t*) cmd, CMD_MAX_SIZE);

                /* pending this 'iob' always (nonce will be used when remote connected). */
                iob->idx = CMD_MAX_SIZE + MAX_NONCE_LEN;
                iob->len = (u32_t) (nread - CMD_MAX_SIZE - MAX_NONCE_LEN);
                ctx->pending_iob = iob;

                if (!is_valid_cmd(cmd)) {
                    xlog_warn("got an error packet (content) from proxy client.");
                    uv_close((uv_handle_t*) stream, on_xclient_closed);

                } else if (cmd->cmd == CMD_CONNECT_CLIENT) {
                    /* find an online client. */
                    pending_ctx_t* pdctx = xhash_get_data(&pending_ctxs, cmd->data);

                    xlog_debug("got CONNECT_CLIENT cmd (%s) from proxy client, process.",
                        devid_to_str(cmd->data));

                    if (pdctx != XHASH_INVALID_DATA) {

                        if (!xlist_empty(&pdctx->clients)) {
                            /* online client exist, associate. */
                            xlog_debug("found an available client, connect to it.");

                            connect_client(ctx, xlist_front(&pdctx->clients));
                            /* move peer (client) node from 'pdctx->clients' to 'peers' */
                            xlist_paste_back(&peers, xlist_cut_front(&pdctx->clients));

                        } else {
                            /* no online client. stop reading from proxy client,
                             * and move it to 'pending_ctx_t'.
                             */
                            xlog_debug("no available client, pending this proxy client.");

                            ctx->pending_ctx = pdctx;

                            uv_read_stop(stream);

                            if (!uv_is_active((uv_handle_t*) &pdctx->timer)) {
                                uv_timer_start(&pdctx->timer, on_connect_client_timeout,
                                    CONNECT_CLIENT_TIMEOUT, 0);
                            }

                            /* move proxy client node from 'xserver_ctxs' to 'pdctx->xclients' */
                            xlist_paste_back(&pdctx->xclients,
                                xlist_cut(&xserver_ctxs, xlist_value_iter(ctx)));
                        }

                    } else {
                        xlog_warn("device_id not exist for proxy client.");
                        uv_close((uv_handle_t*) stream, on_xclient_closed);
                    }

                } else if (cmd->cmd == CMD_CONNECT_IPV4) {
                    struct sockaddr_in remote;

                    remote.sin_family = AF_INET;
                    remote.sin_port = cmd->port;

                    memcpy(&remote.sin_addr, &cmd->data, 4);

                    xlog_debug("got CONNECT_IPV4 cmd (%s) from proxy client, process.",
                        addr_to_str(&remote));

                    /* stop reading from proxy client until remote connected. */
                    uv_read_stop(stream);

                    if (connect_remote(ctx, (struct sockaddr*) &remote) != 0) {
                        /* connect failed immediately, just close this connection. */
                        uv_close((uv_handle_t*) stream, on_xclient_closed);
                    }

                } else if (cmd->cmd == CMD_CONNECT_DOMAIN) {
                    struct addrinfo hints;
                    char portstr[8];
                    uv_getaddrinfo_t* req = xlist_alloc_back(&addrinfo_reqs);

                    hints.ai_family = AF_UNSPEC; /* ipv4 and ipv6 */
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    hints.ai_flags = 0;

                    req->data = ctx;

                    sprintf(portstr, "%d", ntohs(cmd->port));
                    xlog_debug("got CONNECT_DOMAIN cmd (%s) from proxy client, process.",
                        maddr_to_str(cmd));

                    /* stop reading from proxy client until remote connected. */
                    uv_read_stop(stream);

                    if (uv_getaddrinfo(loop, req, on_domain_resolved,
                            (char*) cmd->data, portstr, &hints) != 0) {
                        xlog_error("uv_getaddrinfo (%s) failed immediately.", cmd->data);

                        uv_close((uv_handle_t*) stream, on_xclient_closed);
                        xlist_erase(&addrinfo_reqs, xlist_value_iter(req));
                    }

                } else if (cmd->cmd == CMD_CONNECT_IPV6) {
                    struct sockaddr_in6 remote;

                    remote.sin6_family = AF_INET6;
                    remote.sin6_port = cmd->port;

                    memcpy(&remote.sin6_addr, &cmd->data, 16);

                    xlog_debug("got CONNECT_IPV6 cmd (%s) from proxy client, process.",
                        addr_to_str(&remote));

                    /* stop reading from proxy client until remote connected. */
                    uv_read_stop(stream);

                    if (connect_remote(ctx, (struct sockaddr*) &remote) != 0) {
                        /* connect failed immediately, just close this connection. */
                        uv_close((uv_handle_t*) stream, on_xclient_closed);
                    }

                } else {
                    xlog_warn("got an error command (%d) from proxy client.", cmd->cmd);
                    uv_close((uv_handle_t*) stream, on_xclient_closed);
                }

                /* 'iob' free later. */
                return;
            }

            xlog_warn("got an error packet (length) from proxy client.");
            uv_close((uv_handle_t*) stream, on_xclient_closed);

        } else {
            /* should not reach here */
            xlog_error("unexpected state happen.");
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from proxy client: %s, stage %d.",
            uv_err_name((int) nread), ctx->stage);

        if (ctx->stage == STAGE_FORWARD) {
            uv_close((uv_handle_t*) &ctx->peer->io, on_peer_closed);
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

    ctx->io_xclient.data = ctx;
    ctx->peer = NULL;
    ctx->pending_ctx = NULL;
    ctx->pending_iob = NULL;
    ctx->peer_is_client = 0;
    ctx->xclient_blocked = 0;
    ctx->peer_blocked = 0;
    ctx->stage = STAGE_COMMAND;

    if (uv_accept(stream, (uv_stream_t*) &ctx->io_xclient) == 0) {
        xlog_debug("a proxy client connected.");

        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_iobuf_alloc, on_xclient_read);
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

static void usage(const char* s)
{
    fprintf(stderr, "trp v%d.%d.%d, usage: %s [option]...\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -s <address>  server listen at. (default: 127.0.0.1:%d)\n", DEF_SERVER_PORT);
    fprintf(stderr, "  -x <address>  proxy server listen at. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -m <method>   crypto method, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -k <password> crypto password. (default: none)\n");
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
    fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
    uv_tcp_t io_server;  /* server listen io */
    uv_tcp_t io_xserver; /* proxy-server listen io */
    union { struct sockaddr x; struct sockaddr_in6 d; } addr;
    union { struct sockaddr x; struct sockaddr_in6 d; } xaddr;
    const char* server_str = "127.0.0.1";
    const char* xserver_str = "127.0.0.1";
    const char* logfile = NULL;
    const char* passwd = NULL;
    int method = CRYPTO_CHACHA20;
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
        case 's': server_str  = arg; continue;
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

    if (passwd) {
        derive_key(crypto_key, passwd);
    } else {
        xlog_info("password not set, disable crypto.");
        method = CRYPTO_NONE;
    }

    if (crypto_init(&crypto, method) != 0) {
        xlog_error("invalid crypto method: %d.", method);
        goto end;
    }

    if (parse_ip_str(server_str, DEF_SERVER_PORT, &addr.x) != 0) {
        xlog_error("invalid server address [%s].", server_str);
        goto end;
    }
    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xaddr.x) != 0) {
        xlog_error("invalid proxy server address [%s].", xserver_str);
        goto end;
    }

    uv_tcp_init(loop, &io_server);
    uv_tcp_init(loop, &io_xserver);
    uv_tcp_bind(&io_server, &addr.x, 0);
    uv_tcp_bind(&io_xserver, &xaddr.x, 0);

    error = uv_listen((uv_stream_t*) &io_server,
                LISTEN_BACKLOG, on_client_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.",
            addr_to_str(&addr), uv_strerror(error));
        goto end;
    }

    error = uv_listen((uv_stream_t*) &io_xserver,
                LISTEN_BACKLOG, on_xclient_connect);
    if (error) {
        xlog_error("uv_listen [%s] failed: %s.",
            addr_to_str(&xaddr), uv_strerror(error));
        goto end;
    }

    // http_server_start(loop, "127.0.0.1"); // TODO

    xhash_init(&pending_ctxs, -1, sizeof(pending_ctx_t),
        _pending_ctx_hash, _pending_ctx_equal, NULL);
    xlist_init(&peers, sizeof(peer_t), NULL);
    xlist_init(&xserver_ctxs, sizeof(xserver_ctx_t), NULL);
    xlist_init(&io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);
    xlist_init(&conn_reqs, sizeof(uv_connect_t), NULL);
    xlist_init(&addrinfo_reqs, sizeof(uv_getaddrinfo_t), NULL);

    xlog_info("server listen at [%s]...", addr_to_str(&addr));
    xlog_info("proxy server listen at [%s]...", addr_to_str(&xaddr));
    uv_run(loop, UV_RUN_DEFAULT);

    xlist_destroy(&addrinfo_reqs);
    xlist_destroy(&conn_reqs);
    xlist_destroy(&io_buffers);
    xlist_destroy(&xserver_ctxs);
    xlist_destroy(&peers);
    xhash_destroy(&pending_ctxs);
end:
    xlog_info("end of loop.");
    xlog_exit();

    return 0;
}
