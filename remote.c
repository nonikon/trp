/*
 * Copyright (C) 2021-2025 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>

#include "remote.h"
#ifdef WITH_CTRLSERVER
#include "http_server.h"
#endif

remote_t remote;    /* remote public data */

typedef struct {
    u32_t id;       /* (must be the first member) */
    u8_t alen;      /* addr length */
    u8_t clrcv;     /* CLOSE_ON_RECV flag */
    u8_t alive;
    u8_t refs;
    uv_udp_t io;
    uv_timer_t timer;
    udp_session_t* parent;
} udp_conn_t;

struct udp_session {
    u8_t sid[SESSION_ID_SIZE];  /* (must be the first member) */
    xlist_iter_t iter;          /* the 'remote_ctx_t' used for next udp packet. */
    xlist_t rctxs;              /* remote_ctx_t, udp remote contexts with this sid */
    xhash_t conns;              /* udp_conn_t, udp connections with this sid */
};

#ifdef WITH_CLIREMOTE
struct pending_ctx {
    u8_t devid[DEVICE_ID_SIZE]; /* (must be the first member) */
    xlist_t clients;            /* remote_ctx_t, the clients which at COMMAND stage */
    xlist_t peers;              /* peer_ctx_t, the peers which is connecting to a client */
    uv_timer_t timer;           /* peers connect timeout timer */
    size_t nconnect;
};
#endif

/* remote private data */
static struct {
    xlist_t remote_ctxs;    /* remote_ctx_t */
    xhash_t udp_sessions;   /* udp_session_t */
#ifdef WITH_CLIREMOTE
    xhash_t pending_ctxs;   /* pending_ctx_t */
    size_t nconnect_cli;
#endif
    size_t nconnect_ipv4;
    size_t nconnect_ipv6;
    size_t nconnect_dm;
    size_t nconnect_udp;
} remote_pri;

#ifdef WITH_CLIREMOTE
static void on_cli_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
#endif
static void on_tcp_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&remote.io_buffers);

    buf->base = iob->buffer;
    buf->len = MAX_SOCKBUF_SIZE;
}

void on_peer_closed(uv_handle_t* handle)
{
    peer_ctx_t* ctx = handle->data;

    if (ctx->pending_iob) {
        xlist_erase(&remote.io_buffers, xlist_value_iter(ctx->pending_iob));
    }
    xlist_erase(&remote.peer_ctxs, xlist_value_iter(ctx));

    XLOGD("current %zu peers, %zu iobufs.",
        xlist_size(&remote.peer_ctxs), xlist_size(&remote.io_buffers));
}

void on_peer_write(uv_write_t* req, int status)
{
    peer_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->remote_blocked && status == 0 &&
            uv_stream_get_write_queue_size((uv_stream_t*) &ctx->io) == 0) {
        XLOGD("peer write queue cleared.");

        /* peer write queue cleared, start reading from remote. */
#ifdef WITH_CLIREMOTE
        if (ctx->stage == STAGE_FORWARDCLI) {
            uv_read_start((uv_stream_t*) &ctx->remote->c.io, on_iobuf_alloc,
                on_cli_remote_read);
        } else { /* ctx->stage == STAGE_FORWARDTCP */
#endif
            uv_read_start((uv_stream_t*) &ctx->remote->t.io, on_iobuf_alloc,
                on_tcp_remote_read);
#ifdef WITH_CLIREMOTE
        }
#endif
        ctx->remote_blocked = 0;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

#ifdef WITH_CLIREMOTE
void on_cli_remote_closed(uv_handle_t* handle)
{
    remote_ctx_t* ctx = handle->data;

    if (ctx->c.pending_ctx) {
        /* move client node from 'pending_ctx->clients' to 'remote_ctxs' */
        xlist_paste_back(&remote_pri.remote_ctxs,
            xlist_cut(&ctx->c.pending_ctx->clients, xlist_value_iter(ctx)));

        XLOGD("current %zu pending clients with this devid.",
            xlist_size(&ctx->c.pending_ctx->clients));
    }
    xlist_erase(&remote_pri.remote_ctxs, xlist_value_iter(ctx));

    XLOGD("current %zu remotes, %zu iobufs.",
        xlist_size(&remote_pri.remote_ctxs), xlist_size(&remote.io_buffers));
}

void on_cli_remote_write(uv_write_t* req, int status)
{
    remote_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (status == 0 && ctx->c.peer->peer_blocked &&
            uv_stream_get_write_queue_size((uv_stream_t*) &ctx->c.io) == 0) {
        XLOGD("client remote write queue cleared.");

        /* remote write queue cleared, start reading from peer. */
        uv_read_start((uv_stream_t*) &ctx->c.peer->io, on_iobuf_alloc, on_peer_read);
        ctx->c.peer->peer_blocked = 0;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

static void connect_cli_remote(peer_ctx_t* pctx, remote_ctx_t* rctx)
{
    io_buf_t* iob = pctx->pending_iob;

    rctx->c.peer = pctx;
    rctx->c.pending_ctx = NULL;

    pctx->remote = rctx;
    pctx->pending_iob = NULL;
    pctx->stage = STAGE_FORWARDCLI;

    if (pctx->nodelay) {
        /* enable nodelay both client and peer */
        uv_tcp_nodelay(&pctx->io, 1);
        uv_tcp_nodelay(&rctx->c.io, 1);
    }
    if (iob->len > 0) {
        uv_buf_t wbuf;

        wbuf.base = iob->buffer + iob->idx;
        wbuf.len = iob->len;

        iob->wreq.data = rctx;
        /* write this 'iob' to client, 'iob' free later. */
        uv_write(&iob->wreq, (uv_stream_t*) &rctx->c.io, &wbuf, 1, on_cli_remote_write);
    } else {
        /* free this 'iob' now. */
        xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
    }

    /* disable tcp-keepalive with client. */
    uv_tcp_keepalive(&rctx->c.io, 0, 0);
}

static int invoke_encrypted_cli_remote_command(remote_ctx_t* ctx, char* data, u32_t len)
{
    /* process command from client */
    cmd_t* cmd = (cmd_t*) (data + MAX_NONCE_LEN);

    if (len != CMD_MAX_SIZE + MAX_NONCE_LEN) {
        XLOGW("error packet from client (length).");
        return -1;
    }

    remote.crypto.init(&ctx->c.edctx, remote.crypto_key, (u8_t*) data);
    remote.crypto.decrypt(&ctx->c.edctx, (u8_t*) cmd, CMD_MAX_SIZE);

    if (!check_command_md(cmd)) {
        XLOGW("error packet from client (digest).");
        return -1;
    }

    if (!is_valid_command(cmd)) {
        XLOGW("invalid version: %02X (%u.%u).", cmd->tag, cmd->major, cmd->minor);
        return -1;
    }

    if (cmd->cmd == CMD_REPORT_DEVID) {

        if (is_valid_devid(cmd->data) && !ctx->c.pending_ctx) {
            pending_ctx_t* pdctx = xhash_get_data(&remote_pri.pending_ctxs, cmd->data);

            XLOGD("REPORT_DEVID (%s) cmd from client, process.", devid_to_str(cmd->data));

            if (pdctx == XHASH_INVALID_DATA) {
                XLOGI("device id (%s) not exist, insert.", devid_to_str(cmd->data));

                /* create if not exist maybe unsafe, TODO */
                pdctx = xhash_iter_data(xhash_put_ex(&remote_pri.pending_ctxs,
                            cmd->data, DEVICE_ID_SIZE));

                xlist_init(&pdctx->clients, sizeof(remote_ctx_t), NULL);
                xlist_init(&pdctx->peers, sizeof(peer_ctx_t), NULL);

                uv_timer_init(remote.loop, &pdctx->timer);
                pdctx->nconnect = 0;
            }

            if (xlist_empty(&pdctx->peers)) {
                XLOGD("no pending peer match, move to pending list.");

                ctx->c.pending_ctx = pdctx;
                /* move client node from 'remote_ctxs' to 'pdctx->clients' */
                xlist_paste_back(&pdctx->clients,
                    xlist_cut(&remote_pri.remote_ctxs, xlist_value_iter(ctx)));

            } else {
                XLOGD("pending peer match, associate.");

                connect_cli_remote(xlist_front(&pdctx->peers), ctx);
                ++pdctx->nconnect;
                /* move peer node from 'pdctx->peers' to 'peer_ctxs' */
                xlist_paste_back(&remote.peer_ctxs, xlist_cut_front(&pdctx->peers));

                uv_read_start((uv_stream_t*) &ctx->c.peer->io, on_iobuf_alloc,
                    on_peer_read);

                if (!xlist_empty(&pdctx->peers)) {
                    /* still have some pending peers, reset timer. */
                    uv_timer_again(&pdctx->timer);
                } else {
                    /* no pending peers exist, stop timer. */
                    uv_timer_stop(&pdctx->timer);
                }
            }

            return 0;
        }

        XLOGW("invalid device id from client.");
        return -1;
    }

    XLOGW("error command (%d) from client.", cmd->cmd);
    return -1;
}

static void on_cli_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    remote_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        if (ctx->c.peer != NULL) {
            /* client is already associated with an peer, foward data. */
            uv_buf_t wbuf;
            XLOGD("%zd bytes from client, to proxy client.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->c.peer;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->c.peer->io, &wbuf, 1,
                on_peer_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->c.peer->io) > MAX_WQUEUE_SIZE) {
                XLOGD("peer write queue pending.");

                /* stop reading from client until peer write queue cleared. */
                uv_read_stop(stream);
                ctx->c.peer->remote_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }

        /* ctx->c.peer == NULL */
        if (invoke_encrypted_cli_remote_command(ctx, buf->base, (u32_t) nread) != 0) {
            uv_close((uv_handle_t*) stream, on_cli_remote_closed);
        }

    } else if (nread < 0) {
        XLOGD("disconnected from client: %s.", uv_err_name((int) nread));

        if (ctx->c.peer != NULL) {
            uv_close((uv_handle_t*) &ctx->c.peer->io, on_peer_closed);
        }
        uv_close((uv_handle_t*) stream, on_cli_remote_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

void on_cli_remote_connect(uv_stream_t* stream, int status)
{
    remote_ctx_t* ctx;

    if (status < 0) {
        XLOGE("new connection error: %s.", uv_strerror(status));
        return;
    }
    ctx = xlist_alloc_back(&remote_pri.remote_ctxs);

    uv_tcp_init(remote.loop, &ctx->c.io);

    ctx->c.peer = NULL;
    ctx->c.io.data = ctx;
    ctx->c.pending_ctx = NULL;

    if (uv_accept(stream, (uv_stream_t*) &ctx->c.io) == 0) {
        XLOGD("client connected.");
        /* enable tcp-keepalive with client. */
        uv_tcp_keepalive(&ctx->c.io, 1, KEEPIDLE_TIME);
        uv_read_start((uv_stream_t*) &ctx->c.io, on_iobuf_alloc, on_cli_remote_read);
    } else {
        XLOGE("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->c.io, on_cli_remote_closed);
    }
}

static void on_connect_cli_remote_timeout(uv_timer_t* timer)
{
    pending_ctx_t* ctx = xcontainer_of(timer, pending_ctx_t, timer);

    XLOGI("still no available client after %u seconds, close %zu pending peer(s).",
        CONNECT_CLI_TIMEO, xlist_size(&ctx->peers));

    do {
        peer_ctx_t* x = xlist_cut_front(&ctx->peers);

        /* move this peer node from 'ctx->peers' to 'peer_ctxs'. */
        xlist_paste_back(&remote.peer_ctxs, x);
        /* close this peer. */
        uv_close((uv_handle_t*) &x->io, on_peer_closed);
    }
    while (!xlist_empty(&ctx->peers));

    uv_timer_stop(timer);
}
#endif // WITH_CLIREMOTE

void on_tcp_remote_closed(uv_handle_t* handle)
{
    remote_ctx_t* ctx = handle->data;

    xlist_erase(&remote_pri.remote_ctxs, xlist_value_iter(ctx));

    XLOGD("current %zu remotes, %zu iobufs.",
        xlist_size(&remote_pri.remote_ctxs), xlist_size(&remote.io_buffers));
}

void on_tcp_remote_write(uv_write_t* req, int status)
{
    remote_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (status == 0 && ctx->t.peer->peer_blocked &&
            uv_stream_get_write_queue_size((uv_stream_t*) &ctx->t.io) == 0) {
        XLOGD("tcp remote write queue cleared.");

        /* remote write queue cleared, start reading from peer. */
        uv_read_start((uv_stream_t*) &ctx->t.peer->io, on_iobuf_alloc, on_peer_read);
        ctx->t.peer->peer_blocked = 0;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

static void on_tcp_remote_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    remote_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;
        XLOGD("%zd bytes from tcp remote, to peer.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx->t.peer;

        remote.crypto.encrypt(&ctx->t.edctx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->t.peer->io, &wbuf, 1, on_peer_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->t.peer->io) > MAX_WQUEUE_SIZE) {
            XLOGD("peer write queue pending.");

            /* stop reading from remote until peer write queue cleared. */
            uv_read_stop(stream);
            ctx->t.peer->remote_blocked = 1;
        }
        /* 'iob' free later. */
        return;
    }

    if (nread < 0) {
        XLOGD("disconnected from remote: %s.", uv_err_name((int) nread));

        uv_close((uv_handle_t*) &ctx->t.peer->io, on_peer_closed);
        uv_close((uv_handle_t*) stream, on_tcp_remote_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

static void on_tcp_remote_connected(uv_connect_t* req, int status)
{
    remote_ctx_t* ctx = req->data;

    if (status < 0) {
        XLOGW("connect remote failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before remote connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->t.io, on_tcp_remote_closed);
            uv_close((uv_handle_t*) &ctx->t.peer->io, on_peer_closed);
        // }
    } else {
        io_buf_t* iob = ctx->t.peer->pending_iob;

        XLOGD("remote connected, nodelay %d.", ctx->t.peer->nodelay);

        convert_nonce((u8_t*) iob->buffer);
        remote.crypto.init(&ctx->t.edctx, remote.crypto_key, (u8_t*) iob->buffer);

        if (ctx->t.peer->nodelay) {
            /* enable nodelay both remote and peer */
            uv_tcp_nodelay(&ctx->t.io, 1);
            uv_tcp_nodelay(&ctx->t.peer->io, 1);
        }
        if (iob->len > 0) {
            uv_buf_t wbuf;

            wbuf.base = iob->buffer + iob->idx;
            wbuf.len = iob->len;

            iob->wreq.data = ctx;

            remote.crypto.decrypt(&ctx->t.peer->edctx, (u8_t*) wbuf.base, wbuf.len);
            /* write 'iob' to remote, 'iob' free later. */
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->t.io, &wbuf, 1, on_tcp_remote_write);
        } else {
            /* free this 'iob' now. */
            xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
        }

        uv_read_start((uv_stream_t*) &ctx->t.io, on_iobuf_alloc, on_tcp_remote_read);
        uv_read_start((uv_stream_t*) &ctx->t.peer->io, on_iobuf_alloc, on_peer_read);

        ctx->t.peer->pending_iob = NULL;
        ctx->t.peer->stage = STAGE_FORWARDTCP;
    }

    xlist_erase(&remote.conn_reqs, xlist_value_iter(req));
}

static int connect_tcp_remote(peer_ctx_t* ctx, struct sockaddr* addr)
{
    uv_connect_t* req = xlist_alloc_back(&remote.conn_reqs);
    remote_ctx_t* rctx = xlist_alloc_back(&remote_pri.remote_ctxs);

    uv_tcp_init(remote.loop, &rctx->t.io);

    rctx->t.peer = ctx;
    rctx->t.io.data = rctx;
    req->data = rctx;

    if (uv_tcp_connect(req, &rctx->t.io, addr, on_tcp_remote_connected) == 0) {
        ctx->remote = rctx;
        ctx->stage = STAGE_CONNECT;
        return 0;
    }

    XLOGW("connect remote failed immediately.");

    uv_close((uv_handle_t*) &rctx->t.io, on_tcp_remote_closed);
    xlist_erase(&remote.conn_reqs, xlist_value_iter(req));
    return -1;
}

static inline struct addrinfo* choose_addr(struct addrinfo* res, uint8_t method)
{
    switch (method) {
    case FLG_ADDRPREF_NONE: // not specified, use the first addr
        break;
    case FLG_ADDRPREF_IPV4:
        while (res->ai_family != AF_INET && res->ai_next) {
            res = res->ai_next;
        }
        break;
    case FLG_ADDRPREF_IPV6:
        while (res->ai_family != AF_INET6 && res->ai_next) {
            res = res->ai_next;
        }
        break;
    }
    return res;
}

static void on_tcp_remote_domain_resolved(
        uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    peer_ctx_t* ctx = req->data;

    if (status < 0) {
        XLOGD("resolve domain failed: %s.", uv_err_name(status));
        uv_close((uv_handle_t*) &ctx->io, on_peer_closed);

    } else {
        struct addrinfo* pref = choose_addr(res, ctx->addrpref);
        XLOGD("resolve result: %s, connect.", addr_to_str(pref->ai_addr));

        if (connect_tcp_remote(ctx, pref->ai_addr) != 0) {
            /* connect failed immediately, just close this connection. */
            uv_close((uv_handle_t*) &ctx->io, on_peer_closed);
        }
        uv_freeaddrinfo(res);
    }

    xlist_erase(&remote.addrinfo_reqs, xlist_value_iter(req));
}

static inline void free_udp_session(udp_session_t* sess)
{
    XLOGI("free udp session %x, %zu left.", *(u32_t*) sess->sid,
        xhash_size(&remote_pri.udp_sessions) - 1);

    xlist_destroy(&sess->rctxs);
    xhash_destroy(&sess->conns);
    xhash_remove_data(&remote_pri.udp_sessions, sess);
}

static void on_udp_conn_closed(uv_handle_t* handle)
{
    udp_conn_t* conn = handle->data;
    udp_session_t* sess = conn->parent;

    if (--conn->refs) return; /* conn free later */

    XLOGD("free udp connection %x, %zu left in current session.", conn->id,
        xhash_size(&sess->conns) - 1);

    xhash_remove_data(&sess->conns, conn);
    if (xhash_empty(&sess->conns) && xlist_empty(&sess->rctxs)) {
        /* there is no connection under this session, free it. */
        free_udp_session(sess);
    }
}

static inline void close_udp_conn(udp_conn_t* conn)
{
    uv_close((uv_handle_t*) &conn->io, on_udp_conn_closed);
    uv_close((uv_handle_t*) &conn->timer, on_udp_conn_closed);
}

void close_udp_remote(remote_ctx_t* ctx)
{
    udp_session_t* sess = ctx->u.parent;

    if (ctx->u.last_iob) {
        xlist_erase(&remote.io_buffers, xlist_value_iter(ctx->u.last_iob));
    }
    if (xlist_value_iter(ctx) == sess->iter) {
        sess->iter = xlist_iter_next(sess->iter);
    }
    /* move 'ctx' node from 'sess->rctxs' to 'remote_pri.remote_ctxs'. */
    xlist_paste_back(&remote_pri.remote_ctxs,
        xlist_cut(&sess->rctxs, xlist_value_iter(ctx)));
    xlist_erase(&remote_pri.remote_ctxs, xlist_value_iter(ctx));

    XLOGD("%zu udp remote left in session %x.", xlist_size(&sess->rctxs),
        *(u32_t*) sess->sid);

    if (xlist_empty(&sess->rctxs) && xhash_empty(&sess->conns)) {
        /* there is no connection under this session, free it. */
        free_udp_session(sess);
    }
}

static remote_ctx_t* choose_udp_remote_ctx(udp_session_t* s)
{
    remote_ctx_t* rctx;

    if (!xlist_iter_valid(&s->rctxs, s->iter)) {
        if (xlist_empty(&s->rctxs))
            return NULL; /* no available remote_ctx_t */
        s->iter = xlist_begin(&s->rctxs);
    }

    rctx = xlist_iter_value(s->iter);
    if (xlist_size(&s->rctxs) > 1)
        s->iter = xlist_iter_next(s->iter);
    return rctx;
}

static void on_udp_remote_read(uv_udp_t* io, ssize_t nread, const uv_buf_t* buf,
        const struct sockaddr* addr, unsigned int flags)
{
    udp_conn_t* conn = io->data;
    io_buf_t* iob = xcontainer_of(buf->base - sizeof(udp_cmd_t) - 2 - conn->alen,
                        io_buf_t, buffer);

    if (nread < 0) {
        XLOGW("udp remote read failed: %s.", uv_err_name((int) nread));
        close_udp_conn(conn);

    } else if (!addr) {
        /* 'nread' == 0 and 'addr' == NULL means no more data. */
        XLOGD("udp remote read nothing.");

    } else if (flags & UV_UDP_PARTIAL) {
        conn->alive = 1;
        XLOGW("remote udp packet too large (> %u), drop.", iob->len);

    } else {
        remote_ctx_t* rctx;

        conn->alive = 1;
        XLOGD("%zd bytes from udp remote (%s), id %x, to peer.", nread,
            addr_to_str(addr), conn->id);

        rctx = choose_udp_remote_ctx(conn->parent);

        if (!rctx || uv_stream_get_write_queue_size(
                (uv_stream_t*) &rctx->u.peer->io) > MAX_WQUEUE_SIZE) {
            XLOGD("drop this udp packet: rctx %p.", rctx);

        } else {
            union {
                const struct sockaddr*     vx;
                const struct sockaddr_in*  v4;
                const struct sockaddr_in6* v6;
            } _ =  { addr };
            udp_cmd_t* cmd = (udp_cmd_t*) iob->buffer;
            uv_buf_t wbuf;

            cmd->flag = CMD_TAG;
            cmd->id = conn->id;
            wbuf.base = iob->buffer;

            switch (_.vx->sa_family) {
            case AF_INET:
                cmd->alen = 4;
                cmd->len = htons((u16_t) (4 + 2 + nread));
                memcpy(cmd->data, &_.v4->sin_addr, 4);
                memcpy(cmd->data + 4, &_.v4->sin_port, 2);

                wbuf.len = sizeof(udp_cmd_t) + 4 + 2 + nread;
                break;
            default: /* AF_INET6 */
                cmd->alen = 16;
                cmd->len = htons((u16_t) (16 + 2 + nread));
                memcpy(cmd->data, &_.v6->sin6_addr, 16);
                memcpy(cmd->data + 16, &_.v6->sin6_port, 2);

                wbuf.len = sizeof(udp_cmd_t) + 16 + 2 + nread;
                break;
            }
            remote.crypto.encrypt(&rctx->u.edctx, (u8_t*) wbuf.base, wbuf.len);

            iob->wreq.data = rctx->u.peer;
            uv_write(&iob->wreq, (uv_stream_t*) &rctx->u.peer->io,
                &wbuf, 1, on_peer_write);

            if (conn->clrcv) {
                /* close connection on first packet received. */
                close_udp_conn(conn);
            }
            /* 'iob' free later. */
            return;
        }
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

static void on_udp_conn_check(uv_timer_t* timer)
{
    udp_conn_t* conn = timer->data;

    if (!conn->alive) {
        XLOGD("udp connection %x is not alive, close.", conn->id);
        close_udp_conn(conn);
    } else {
        conn->alive = 0;
    }
}

static void on_udp_remote_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&remote.io_buffers);
    udp_conn_t* conn = handle->data;

    /* leave 'sizeof(udp_cmd_t) + conn->alen + 2' bytes space at the beginning. */
    buf->base = iob->buffer + conn->alen + 2 + sizeof(udp_cmd_t);
    buf->len = MAX_SOCKBUF_SIZE - sizeof(udp_cmd_t) - 2 - conn->alen;
}

static void send_udp_packet(remote_ctx_t* ctx, udp_cmd_t* cmd)
{
    union {
        struct sockaddr     vx;
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } addr;
    int rt;
    uv_buf_t wbuf;
    udp_conn_t* conn;

    switch (cmd->alen) {
    case 4:
        addr.v4.sin_family = AF_INET;
        memcpy(&addr.v4.sin_addr, cmd->data, 4);
        memcpy(&addr.v4.sin_port, cmd->data + 4, 2);

        wbuf.base = (char*) (cmd->data + 4 + 2);
        wbuf.len = ntohs(cmd->len) - 4 - 2;
        break;
    case 16:
        addr.v6.sin6_family = AF_INET6;
        memcpy(&addr.v6.sin6_addr, cmd->data, 16);
        memcpy(&addr.v6.sin6_port, cmd->data + 16, 2);

        wbuf.base = (char*) (cmd->data + 16 + 2);
        wbuf.len = ntohs(cmd->len) - 16 - 2;
        break;
    default:
        XLOGW("error udp packet addrlen (%u).", cmd->alen);
        return;
    }
    /* 'wbuf.len' == 0 is allowed. */

    XLOGD("udp packet to %s %u bytes, id %x.", addr_to_str(&addr),
        wbuf.len, cmd->id);

    conn = xhash_get_data(&ctx->u.parent->conns, &cmd->id);

    if (conn != XHASH_INVALID_DATA) {
        if (!uv_is_closing((uv_handle_t*) &conn->io)) {
            /* ignore 'cmd->flag' in the following packets. */
            conn->alive = 1;
            rt = uv_udp_try_send(&conn->io, &wbuf, 1, &addr.vx);
            if (rt < 0) {
                XLOGD("send udp packet failed: %s.", uv_err_name(rt));
            }
        } else {
            /* 'uv_close' was called on this UDP connection. */
            XLOGD("udp connection is closing, drop this packet.");
        }

    } else {
        XLOGD("new udp connection, id %x.", cmd->id);

        conn = xhash_iter_data(xhash_put_ex(&ctx->u.parent->conns,
                    &cmd->id, sizeof(u32_t)));

        uv_udp_init(remote.loop, &conn->io);
        uv_timer_init(remote.loop, &conn->timer);
        /* enable to send udp broadcast packet. */
        uv_udp_set_broadcast(&conn->io, 1);
  
        conn->alen = cmd->alen;
        conn->clrcv = cmd->flag >> 7;
        conn->alive = 0;
        conn->refs = 2;
        conn->io.data = conn;
        conn->timer.data = conn;
        conn->parent = ctx->u.parent;

        rt = uv_udp_try_send(&conn->io, &wbuf, 1, &addr.vx);
        if (rt < 0) {
            XLOGW("send first udp packet failed: %s.", uv_err_name(rt));
            close_udp_conn(conn);
        } else {
            rt = cmd->flag & 0x7F; /* UDP connection timeout (seconds) */
            rt = rt == 0 || rt > MAX_UDPCONN_TIMEO ? MAX_UDPCONN_TIMEO * 1000 : rt * 1000;

            uv_udp_recv_start(&conn->io, on_udp_remote_rbuf_alloc, on_udp_remote_read);
            uv_timer_start(&conn->timer, on_udp_conn_check, rt, rt);
        }
    }
}

static int __iob_move(io_buf_t* dst, io_buf_t* src, u32_t need)
{
    if (dst->len + src->len < need) {
        memcpy(dst->buffer + dst->len, src->buffer + src->idx, src->len);
        dst->len += src->len;
        return -1;
    }
    need -= dst->len;
    memcpy(dst->buffer + dst->len, src->buffer + src->idx, need);
    dst->len += need;
    src->len -= need;
    src->idx += need;
    return 0;
}

int forward_peer_udp_packets(remote_ctx_t* ctx, io_buf_t* iob)
{
    udp_cmd_t* cmd;
    u32_t need;

    if (ctx->u.last_iob) {
        io_buf_t* last_iob = ctx->u.last_iob;

        /* 'last_iob->idx' is always zero. */
        if (last_iob->len < sizeof(udp_cmd_t)
                && __iob_move(last_iob, iob, sizeof(udp_cmd_t)) != 0)
            return 0;

        cmd = (udp_cmd_t*) last_iob->buffer;
        need = ntohs(cmd->len) + sizeof(udp_cmd_t);

        if (need > MAX_SOCKBUF_SIZE || need < cmd->alen + 2 + sizeof(udp_cmd_t)) {
            XLOGW("error udp packet length (%u).", need);

            ctx->u.last_iob = NULL;
            xlist_erase(&remote.io_buffers, xlist_value_iter(last_iob));
            return 0;
        }

        if (__iob_move(last_iob, iob, need) != 0)
            return 0;

        send_udp_packet(ctx, cmd);

        ctx->u.last_iob = NULL;
        xlist_erase(&remote.io_buffers, xlist_value_iter(last_iob));
    }

    while (iob->len > sizeof(udp_cmd_t)) {
        cmd = (udp_cmd_t*) (iob->buffer + iob->idx);
        need = ntohs(cmd->len) + sizeof(udp_cmd_t);

        if (need > MAX_SOCKBUF_SIZE || need < cmd->alen + 2 + sizeof(udp_cmd_t)) {
            XLOGW("error udp packet length (%u).", need);
            return 0;
        }
        if (iob->len < need) {
            /* udp packet need more. */
            break;
        }
        send_udp_packet(ctx, cmd);

        iob->idx += need;
        iob->len -= need;
    }

    if (iob->len) {
        if (iob->idx) {
            memmove(iob->buffer, iob->buffer + iob->idx, iob->len);
            iob->idx = 0;
        }
        XLOGD("%u udp bytes left.", iob->len);

        ctx->u.last_iob = iob;
        return 1;
    }

    return 0;
}

static unsigned __udp_conn_hash(void* v)
{
    return xhash_data_hash(v, sizeof(u32_t));
}

static int __udp_conn_equal(void* l, void* r)
{
    return *(u32_t*) l == *(u32_t*) r;
}

static void connect_udp_remote(peer_ctx_t* ctx, const u8_t* sid)
{
    udp_session_t* sess = xhash_get_data(&remote_pri.udp_sessions, sid);
    io_buf_t* iob = ctx->pending_iob;
    remote_ctx_t* rctx;

    if (sess == XHASH_INVALID_DATA) {
        XLOGI("new udp session %x.", *(u32_t*) sid);

        /* the number of sessions may need to be limited, TODO. */
        sess = xhash_iter_data(xhash_put_ex(&remote_pri.udp_sessions,
                    sid, SESSION_ID_SIZE));

        xlist_init(&sess->rctxs, sizeof(remote_ctx_t), NULL);
        xhash_init(&sess->conns, -1, sizeof(udp_conn_t), __udp_conn_hash,
            __udp_conn_equal, NULL);

        sess->iter = xlist_end(&sess->rctxs);
    }

    rctx = xlist_alloc_back(&remote_pri.remote_ctxs);
    /* move 'rctx' node from 'remote_pri.remote_ctxs' to 'sess->rctxs'. */
    xlist_paste_back(&sess->rctxs,
        xlist_cut(&remote_pri.remote_ctxs, xlist_value_iter(rctx)));

    rctx->u.peer = ctx;
    rctx->u.parent = sess;
    rctx->u.last_iob = NULL;

    convert_nonce((u8_t*) iob->buffer);
    remote.crypto.init(&rctx->u.edctx, remote.crypto_key, (u8_t*) iob->buffer);

    ctx->remote = rctx;
    ctx->pending_iob = NULL;
    ctx->stage = STAGE_FORWARDUDP;

    if (iob->len) {
        remote.crypto.decrypt(&ctx->edctx, (u8_t*) iob->buffer + iob->idx, iob->len);

        if (forward_peer_udp_packets(ctx->remote, iob) != 0) {
            /* some bytes left, 'iob' free later. */
            return;
        }
    }
    /* 'iob' was processed totally, release now. */
    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

/* process command from peer. */
int invoke_encrypted_peer_command(peer_ctx_t* ctx, io_buf_t* iob)
{
    cmd_t* cmd = (cmd_t*) (iob->buffer + MAX_NONCE_LEN);

    /* pending this 'iob' always (nonce will be used when remote connected). */
    ctx->pending_iob = iob;

    if (iob->len < CMD_MAX_SIZE + MAX_NONCE_LEN) {
        XLOGW("error packet from peer (length).");
        return -1;
    }

    remote.crypto.init(&ctx->edctx, remote.crypto_key, (u8_t*) iob->buffer);
    remote.crypto.decrypt(&ctx->edctx, (u8_t*) cmd, CMD_MAX_SIZE);

    iob->idx = CMD_MAX_SIZE + MAX_NONCE_LEN;
    iob->len -= CMD_MAX_SIZE + MAX_NONCE_LEN;

    if (!check_command_md(cmd)) {
        XLOGW("error packet from client (digest).");
        return -1;
    }

    if (!is_valid_command(cmd)) {
        XLOGW("invalid version: %02X (%u.%u).", cmd->tag, cmd->major, cmd->minor);
        return -1;
    }

    ctx->nodelay = (cmd->flag >> 2) & 0x01;
    ctx->addrpref = cmd->flag & 0x03;
#ifdef WITH_CLIREMOTE
    if (cmd->cmd == CMD_CONNECT_CLIENT) {
        /* find an online client. */
        pending_ctx_t* pdctx = xhash_get_data(&remote_pri.pending_ctxs, cmd->data);

        ++remote_pri.nconnect_cli;
        XLOGD("CONNECT_CLIENT cmd (%s, %d) from peer, process.",
            devid_to_str(cmd->data), cmd->flag);

        if (pdctx != XHASH_INVALID_DATA) {

            if (!xlist_empty(&pdctx->clients)) {
                /* online client exist, associate. */
                XLOGD("found an available client, connect.");

                connect_cli_remote(ctx, xlist_front(&pdctx->clients));
                ++pdctx->nconnect;
                /* move client node from 'pdctx->clients' to 'remote_ctxs' */
                xlist_paste_back(&remote_pri.remote_ctxs, xlist_cut_front(&pdctx->clients));

            } else {
                /* no online client. stop reading from peer and move it to 'pending_ctx_t'. */
                XLOGD("no available client, pending this peer.");

                uv_read_stop((uv_stream_t*) &ctx->io);
                /* move peer node from 'peer_ctxs' to 'pdctx->peers' */
                xlist_paste_back(&pdctx->peers,
                    xlist_cut(&remote.peer_ctxs, xlist_value_iter(ctx)));

                if (!uv_is_active((uv_handle_t*) &pdctx->timer)) {
                    uv_timer_start(&pdctx->timer, on_connect_cli_remote_timeout,
                        CONNECT_CLI_TIMEO * 1000, CONNECT_CLI_TIMEO * 1000);
                }
                ctx->pending_ctx = pdctx;
            }

            return 0;
        }

        XLOGW("device id (%s) not exist for peer.", devid_to_str(cmd->data));
        return -1;
    }

    if (remote.dconnect_off) {
        XLOGD("attempt to connect %s directly but function is disabled.",
            maddr_to_str(cmd));
        return -1;
    }
#endif

    if (cmd->cmd == CMD_CONNECT_IPV4) {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = cmd->port;

        memcpy(&addr.sin_addr, cmd->data, 4);

        ++remote_pri.nconnect_ipv4;
        XLOGD("CONNECT_IPV4 cmd (%s, %d) from peer, process.", addr_to_str(&addr), cmd->flag);

        /* stop reading from peer until remote connected. */
        uv_read_stop((uv_stream_t*) &ctx->io);

        if (connect_tcp_remote(ctx, (struct sockaddr*) &addr) == 0)
            return 0;
        /* connect failed immediately. */
        return -1;
    }

    if (cmd->cmd == CMD_CONNECT_DOMAIN) {
        struct addrinfo hints;
        char portstr[8];
        uv_getaddrinfo_t* req = xlist_alloc_back(&remote.addrinfo_reqs);

        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_UNSPEC; /* ipv4 and ipv6 */
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = 0;

        req->data = ctx;
        /* make sure that domain is null-terminated. */
        cmd->data[MAX_DOMAIN_LEN - 1] = 0;

        sprintf(portstr, "%d", ntohs(cmd->port));
        ++remote_pri.nconnect_dm;
        XLOGD("CONNECT_DOMAIN cmd (%s, %d) from peer, process.", maddr_to_str(cmd), cmd->flag);

        /* stop reading from peer until remote connected. */
        uv_read_stop((uv_stream_t*) &ctx->io);

        if (uv_getaddrinfo(remote.loop, req, on_tcp_remote_domain_resolved,
                (char*) cmd->data, portstr, &hints) == 0)
            return 0;

        XLOGW("uv_getaddrinfo (%s) failed immediately.", cmd->data);
        xlist_erase(&remote.addrinfo_reqs, xlist_value_iter(req));
        return -1;
    }

    if (cmd->cmd == CMD_CONNECT_IPV6) {
        struct sockaddr_in6 addr;

        addr.sin6_family = AF_INET6;
        addr.sin6_port = cmd->port;

        memcpy(&addr.sin6_addr, cmd->data, 16);

        ++remote_pri.nconnect_ipv6;
        XLOGD("CONNECT_IPV6 cmd (%s, %d) from peer, process.", addr_to_str(&addr), cmd->flag);

        /* stop reading from peer until remote connected. */
        uv_read_stop((uv_stream_t*) &ctx->io);

        if (connect_tcp_remote(ctx, (struct sockaddr*) &addr) == 0)
            return 0;
        /* connect failed immediately. */
        return -1;
    }

    if (cmd->cmd == CMD_CONNECT_UDP) {
        ++remote_pri.nconnect_udp;
        XLOGD("CONNECT_UDP cmd (%s, %d) from peer, process.", maddr_to_str(cmd), cmd->flag);
        connect_udp_remote(ctx, cmd->data);
        return 0;
    }

    XLOGW("error command (%d) from peer.", cmd->cmd);
    return -1;
}

#ifdef WITH_CTRLSERVER
static void handle_request_index(const http_request_t* req, http_response_t* resp);
static void handle_request_status(const http_request_t* req, http_response_t* resp);
static void handle_request_usession_list(const http_request_t* req, http_response_t* resp);
#ifdef WITH_CLIREMOTE
static void handle_request_device_list(const http_request_t* req, http_response_t* resp);
static void handle_request_dconnect_on(const http_request_t* req, http_response_t* resp);
static void handle_request_dconnect_off(const http_request_t* req, http_response_t* resp);
#endif
static void handle_request_log_verbose_on(const http_request_t* req, http_response_t* resp);
static void handle_request_log_verbose_off(const http_request_t* req, http_response_t* resp);

static const http_handler_t __ctrl_server_handler[] = {
    { "/", handle_request_index },
    { "/status", handle_request_status },
    { "/usession/list", handle_request_usession_list },
#ifdef WITH_CLIREMOTE
    { "/device/list", handle_request_device_list },
    { "/dconnect/on", handle_request_dconnect_on },
    { "/dconnect/off", handle_request_dconnect_off },
#endif
    { "/log/verbose/on", handle_request_log_verbose_on },
    { "/log/verbose/off", handle_request_log_verbose_off },
    { NULL, NULL }
};

/* get the control server api list. */
static void handle_request_index(const http_request_t* req, http_response_t* resp)
{
    const http_handler_t* h = __ctrl_server_handler;

    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: text/html\r\n");

    http_buf_add_string(resp->body, &resp->body_len,
        "<html><head><title>API List</title></head><body>\n");
    while (h->path) {
        http_buf_add_printf(resp->body, &resp->body_len,
            "<p><a href=\"%s\">%s</a></p>\n", h->path, h->path);
        ++h;
    }
    http_buf_add_string(resp->body, &resp->body_len, "</body></html>");
}

static void handle_request_status(const http_request_t* req, http_response_t* resp)
{
    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");

    http_buf_add_printf(resp->body, &resp->body_len, "{\n"
        "\"peer_ctxs\":%zd,\n"
        "\"remote_ctxs\":%zd,\n"
        "\"io_buffers\":%zd,\n"
        "\"udp_sessions\":%zd,\n"
#ifdef WITH_CLIREMOTE
        "\"devices\":%zd,\n"
        "\"nconnect_cli\":%zd,\n"
#endif
        "\"nconnect_ipv4\":%zd,\n"
        "\"nconnect_ipv6\":%zd,\n"
        "\"nconnect_dm\":%zd,\n"
        "\"nconnect_udp\":%zd\n}",
        xlist_size(&remote.peer_ctxs),
        xlist_size(&remote_pri.remote_ctxs),
        xlist_size(&remote.io_buffers),
        xhash_size(&remote_pri.udp_sessions),
#ifdef WITH_CLIREMOTE
        xhash_size(&remote_pri.pending_ctxs),
        remote_pri.nconnect_cli,
#endif
        remote_pri.nconnect_ipv4,
        remote_pri.nconnect_ipv6,
        remote_pri.nconnect_dm,
        remote_pri.nconnect_udp);
}

static void handle_request_usession_list(const http_request_t* req, http_response_t* resp)
{
    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");

    http_buf_add_string(resp->body, &resp->body_len, "[\n");

    if (!xhash_empty(&remote_pri.udp_sessions)) {
        xhash_iter_t iter = xhash_begin(&remote_pri.udp_sessions);

        do {
            udp_session_t* s = xhash_iter_data(iter);

            http_buf_add_printf(resp->body, &resp->body_len,
                "{\"sid\":\"%x\",\"nrctxs\":%zd,\"nconns\":%zd},\n",
                *(u32_t*) s->sid, xlist_size(&s->rctxs), xhash_size(&s->conns));

            iter = xhash_iter_next(&remote_pri.udp_sessions, iter);
        }
        while (xhash_iter_valid(iter) && resp->body_len + 64 <= sizeof(resp->body));

        resp->body_len -= 2; /* delete ',\n' at the end of 'resp->body'. */
    }
    http_buf_add_string(resp->body, &resp->body_len, "\n]");
}

#ifdef WITH_CLIREMOTE
static void handle_request_device_list(const http_request_t* req, http_response_t* resp)
{
    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");

    http_buf_add_string(resp->body, &resp->body_len, "[\n");

    if (!xhash_empty(&remote_pri.pending_ctxs)) {
        xhash_iter_t iter = xhash_begin(&remote_pri.pending_ctxs);

        do {
            pending_ctx_t* c = xhash_iter_data(iter);

            http_buf_add_printf(resp->body, &resp->body_len,
                "{\"devid\":\"%s\",\"nclients\":%zd,\"npeers\":%zd,\"nconnect\":%zd},\n",
                devid_to_str(c->devid), xlist_size(&c->clients), xlist_size(&c->peers),
                c->nconnect);

            iter = xhash_iter_next(&remote_pri.pending_ctxs, iter);
        }
        while (xhash_iter_valid(iter)
            && resp->body_len + 110 + DEVICE_ID_SIZE <= sizeof(resp->body));

        resp->body_len -= 2; /* delete ',\n' at the end of 'resp->body'. */
    }
    http_buf_add_string(resp->body, &resp->body_len, "\n]");
}

static void handle_request_dconnect_on(const http_request_t* req, http_response_t* resp)
{
    remote.dconnect_off = 0;
    XLOGW("direct connect [ON].");

    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");
    http_buf_add_string(resp->body, &resp->body_len, "{\"code\":0}\n");
}

static void handle_request_dconnect_off(const http_request_t* req, http_response_t* resp)
{
    remote.dconnect_off = 1;
    XLOGW("direct connect [OFF].");

    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");
    http_buf_add_string(resp->body, &resp->body_len, "{\"code\":0}\n");
}
#endif // WITH_CLIREMOTE

static void handle_request_log_verbose_on(const http_request_t* req, http_response_t* resp)
{
    xlog_ctrl(XLOG_DEBUG, 0, 0);
    XLOGW("output verbosely [ON].");

    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");
    http_buf_add_string(resp->body, &resp->body_len, "{\"code\":0}\n");
}

static void handle_request_log_verbose_off(const http_request_t* req, http_response_t* resp)
{
    xlog_ctrl(XLOG_INFO, 0, 0);
    XLOGW("output verbosely [OFF].");

    http_buf_add_string(resp->headers, &resp->header_len,
        "Content-Type: application/json\r\n");
    http_buf_add_string(resp->body, &resp->body_len, "{\"code\":0}\n");
}

int start_ctrl_server(uv_loop_t* loop, const char* addrstr)
{
    union {
        struct sockaddr x;
        struct sockaddr_in6 d;
    } addr;

    if (parse_ip_str(addrstr, DEF_CSERVER_PORT, &addr.x) != 0) {
        XLOGE("invalid control server address (%s).", addrstr);
        return -1;
    }

    return http_server_start(loop, &addr.x, __ctrl_server_handler);
}
#endif // WITH_CTRLSERVER

#ifdef WITH_CLIREMOTE
static unsigned __pending_ctx_hash(void* v)
{
    return xhash_data_hash(v, DEVICE_ID_SIZE);
}
static int __pending_ctx_equal(void* l, void* r)
{
    return !memcmp(l, r, DEVICE_ID_SIZE);
}
#endif

static unsigned __udp_session_hash(void* v)
{
    /* first 4 bytes of session id. */
    return xhash_improve_hash(*(unsigned*) v);
}
static int __udp_session_equal(void* l, void* r)
{
    return !memcmp(l, r, SESSION_ID_SIZE);
}

void remote_private_init()
{
    xlist_init(&remote_pri.remote_ctxs, sizeof(remote_ctx_t), NULL);
#ifdef WITH_CLIREMOTE
    xhash_init(&remote_pri.pending_ctxs, -1, sizeof(pending_ctx_t),
        __pending_ctx_hash, __pending_ctx_equal, NULL);
#endif
    xhash_init(&remote_pri.udp_sessions, -1, sizeof(udp_session_t),
        __udp_session_hash, __udp_session_equal, NULL);
}

void remote_private_destroy()
{
    xhash_destroy(&remote_pri.udp_sessions);
#ifdef WITH_CLIREMOTE
    xhash_destroy(&remote_pri.pending_ctxs);
#endif
    xlist_destroy(&remote_pri.remote_ctxs);
}