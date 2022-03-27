/*
 * Copyright (C) 2021-2022 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>

#include "remote.h"

remote_t remote;

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

    xlog_debug("current %zd peers, %zd iobufs.",
        xlist_size(&remote.peer_ctxs), xlist_size(&remote.io_buffers));
}

void on_peer_write(uv_write_t* req, int status)
{
    peer_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->remote_blocked && status == 0 &&
            uv_stream_get_write_queue_size((uv_stream_t*) &ctx->io) == 0) {
        xlog_debug("peer write queue cleared.");

        /* peer write queue cleared, start reading from remote. */
#ifdef WITH_CLIREMOTE
        if (ctx->stage == STAGE_FORWARDCLI) {
            uv_read_start((uv_stream_t*) &ctx->remote->c.io,
                on_iobuf_alloc, on_cli_remote_read);
        } else { /* ctx->stage == STAGE_FORWARDTCP */
#endif
            uv_read_start((uv_stream_t*) &ctx->remote->t.io,
                on_iobuf_alloc, on_tcp_remote_read);
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
        xlist_paste_back(&remote.remote_ctxs,
            xlist_cut(&ctx->c.pending_ctx->clients, xlist_value_iter(ctx)));

        xlog_debug("current %zd pending clients with this devid.",
            xlist_size(&ctx->c.pending_ctx->clients));
    }
    xlist_erase(&remote.remote_ctxs, xlist_value_iter(ctx));

    xlog_debug("current %zd remotes, %zd iobufs.",
        xlist_size(&remote.remote_ctxs), xlist_size(&remote.io_buffers));
}

void on_cli_remote_write(uv_write_t* req, int status)
{
    remote_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (status == 0 && ctx->c.peer->peer_blocked &&
            uv_stream_get_write_queue_size((uv_stream_t*) &ctx->c.io) == 0) {
        xlog_debug("client remote write queue cleared.");

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
        xlog_warn("got an error packet (length) from client.");
        return -1;
    }

    remote.crypto.init(&ctx->c.edctx, remote.crypto_key, (u8_t*) data);
    remote.crypto.decrypt(&ctx->c.edctx, (u8_t*) cmd, CMD_MAX_SIZE);

    if (!is_valid_command(cmd)) {
        xlog_warn("got an error packet (header) from client.");
        return -1;
    }

    if (cmd->cmd == CMD_REPORT_DEVID) {

        if (is_valid_devid(cmd->data) && !ctx->c.pending_ctx) {
            pending_ctx_t* pdctx = xhash_get_data(&remote.pending_ctxs, cmd->data);

            xlog_debug("got REPORT_DEVID (%s) cmd from client, process.",
                devid_to_str(cmd->data));

            if (pdctx == XHASH_INVALID_DATA) {
                xlog_info("device_id [%s] not exist, insert.", devid_to_str(cmd->data));

                /* create if not exist maybe unsafe, TODO */
                pdctx = xhash_iter_data(xhash_put_ex(&remote.pending_ctxs,
                            cmd->data, DEVICE_ID_SIZE));

                xlist_init(&pdctx->clients, sizeof(remote_ctx_t), NULL);
                xlist_init(&pdctx->peers, sizeof(peer_ctx_t), NULL);

                uv_timer_init(remote.loop, &pdctx->timer);
            }

            if (xlist_empty(&pdctx->peers)) {
                xlog_debug("no pending peer match, move to pending list.");

                ctx->c.pending_ctx = pdctx;
                /* move client node from 'remote_ctxs' to 'pdctx->clients' */
                xlist_paste_back(&pdctx->clients,
                    xlist_cut(&remote.remote_ctxs, xlist_value_iter(ctx)));

            } else {
                xlog_debug("pending peer match, associate.");

                connect_cli_remote(xlist_front(&pdctx->peers), ctx);
                /* move peer node from 'pdctx->peers' to 'peer_ctxs' */
                xlist_paste_back(&remote.peer_ctxs, xlist_cut_front(&pdctx->peers));

                uv_read_start((uv_stream_t*) &ctx->c.peer->io,
                    on_iobuf_alloc, on_peer_read);

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

        xlog_warn("invalid device id from client.");
        return -1;
    }

    xlog_warn("got an error command (%d) from client.", cmd->cmd);
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

            xlog_debug("recved %zd bytes from client, forward.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx->c.peer;

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->c.peer->io,
                &wbuf, 1, on_peer_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->c.peer->io) > MAX_WQUEUE_SIZE) {
                xlog_debug("peer write queue pending.");

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
        xlog_debug("disconnected from client: %s.", uv_err_name((int) nread));

        if (ctx->c.peer != NULL) {
            uv_close((uv_handle_t*) &ctx->c.peer->io, on_peer_closed);
        }
        uv_close((uv_handle_t*) stream, on_cli_remote_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0.
         * just 'return' in this situation.
         */
        if (!buf->base) return;
    }

    xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
}

void on_cli_remote_connect(uv_stream_t* stream, int status)
{
    remote_ctx_t* ctx;

    if (status < 0) {
        xlog_error("new connection error: %s.", uv_strerror(status));
        return;
    }

    ctx = xlist_alloc_back(&remote.remote_ctxs);

    uv_tcp_init(remote.loop, &ctx->c.io);

    ctx->c.peer = NULL;
    ctx->c.io.data = ctx;
    ctx->c.pending_ctx = NULL;

    if (uv_accept(stream, (uv_stream_t*) &ctx->c.io) == 0) {
        xlog_debug("a client connected.");
        /* enable tcp-keepalive with client. */
        uv_tcp_keepalive(&ctx->c.io, 1, KEEPIDLE_TIME);
        uv_read_start((uv_stream_t*) &ctx->c.io, on_iobuf_alloc, on_cli_remote_read);
    } else {
        xlog_error("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->c.io, on_cli_remote_closed);
    }
}

static void on_connect_cli_remote_timeout(uv_timer_t* timer)
{
    pending_ctx_t* ctx = xcontainer_of(timer, pending_ctx_t, timer);

    xlog_debug("still no available client after %d seconds, close %zd pending peer(s).",
        CONNECT_CLI_TIMEO / 1000, xlist_size(&ctx->peers));

    do {
        peer_ctx_t* x = xlist_cut_front(&ctx->peers);

        /* move this peer node from 'ctx->peers' to 'peer_ctxs'. */
        xlist_paste_back(&remote.peer_ctxs, x);
        /* close this peer. */
        uv_close((uv_handle_t*) &x->io, on_peer_closed);
    }
    while (!xlist_empty(&ctx->peers));

    /* timer is already stopped. */
    // uv_timer_stop(timer);
}
#endif // WITH_CLIREMOTE

void on_tcp_remote_closed(uv_handle_t* handle)
{
    remote_ctx_t* ctx = handle->data;

    xlist_erase(&remote.remote_ctxs, xlist_value_iter(ctx));

    xlog_debug("current %zd remotes, %zd iobufs.",
        xlist_size(&remote.remote_ctxs), xlist_size(&remote.io_buffers));
}

void on_tcp_remote_write(uv_write_t* req, int status)
{
    remote_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (status == 0 && ctx->t.peer->peer_blocked &&
            uv_stream_get_write_queue_size((uv_stream_t*) &ctx->t.io) == 0) {
        xlog_debug("tcp remote write queue cleared.");

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

        xlog_debug("recved %zd bytes from remote, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx->t.peer;

        remote.crypto.encrypt(&ctx->t.edctx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->t.peer->io,
            &wbuf, 1, on_peer_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->t.peer->io) > MAX_WQUEUE_SIZE) {
            xlog_debug("peer write queue pending.");

            /* stop reading from remote until peer write queue cleared. */
            uv_read_stop(stream);
            ctx->t.peer->remote_blocked = 1;
        }

        /* 'iob' free later. */
        return;
    }

    if (nread < 0) {
        xlog_debug("disconnected from remote: %s.", uv_err_name((int) nread));

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
        xlog_error("connect remote failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before remote connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->t.io, on_tcp_remote_closed);
            uv_close((uv_handle_t*) &ctx->t.peer->io, on_peer_closed);
        // }

    } else {
        io_buf_t* iob = ctx->t.peer->pending_iob;

        xlog_debug("remote connected.");

        convert_nonce((u8_t*) iob->buffer);
        remote.crypto.init(&ctx->t.edctx, remote.crypto_key, (u8_t*) iob->buffer);

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
    remote_ctx_t* rctx = xlist_alloc_back(&remote.remote_ctxs);

    uv_tcp_init(remote.loop, &rctx->t.io);

    rctx->t.peer = ctx;
    rctx->t.io.data = rctx;
    req->data = rctx;

    if (uv_tcp_connect(req, &rctx->t.io, addr, on_tcp_remote_connected) == 0) {
        ctx->remote = rctx;
        ctx->stage = STAGE_CONNECT;
        return 0;
    }

    xlog_error("connect remote failed immediately.");

    uv_close((uv_handle_t*) &rctx->t.io, on_tcp_remote_closed);
    xlist_erase(&remote.conn_reqs, xlist_value_iter(req));
    return -1;
}

static void on_tcp_remote_domain_resolved(
        uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    peer_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_debug("resolve domain failed: %s.", uv_err_name(status));
        uv_close((uv_handle_t*) &ctx->io, on_peer_closed);

    } else {
        xlog_debug("resolve result [%s], connect it.", addr_to_str(res->ai_addr));

        if (connect_tcp_remote(ctx, res->ai_addr) != 0) {
            /* connect failed immediately, just close this connection. */
            uv_close((uv_handle_t*) &ctx->io, on_peer_closed);
        }
        uv_freeaddrinfo(res);
    }

    xlist_erase(&remote.addrinfo_reqs, xlist_value_iter(req));
}

static void free_udp_remote(remote_ctx_t* ctx)
{
    udp_sess_t* sess = ctx->u.parent;

    xlog_debug("%zd udp remote left in current session, free one.",
        xlist_size(&sess->rctxs));

    xlist_erase(&remote.io_buffers, xlist_value_iter(ctx->u.rbuf));
    xlist_erase(&sess->rctxs, xlist_value_iter(ctx));

    if (xlist_empty(&sess->rctxs) && xhash_empty(&sess->conns)) {
        /* there is no connection under this session, free session. */
        xlist_destroy(&sess->rctxs);
        xhash_destroy(&sess->conns);

        xhash_remove_data(&remote.udp_sessions, sess);
    }
}

static void on_udp_conn_closed(uv_handle_t* handle)
{
    udp_conn_t* conn = handle->data;
    remote_ctx_t* ctx = conn->parent;

    xlog_debug("%zd udp connection left in current session, free one (%x).",
        xhash_size(&ctx->u.parent->conns), conn->id);

    xhash_remove_data(&ctx->u.parent->conns, conn);

    if (--ctx->u.nconns == 0 && !ctx->u.peer) {
        /* there is no connection under this udp remote
         * and peer has been closed. free udp remote.
         */
        free_udp_remote(ctx);
    }
}

static inline void close_udp_conn(udp_conn_t* conn)
{
    uv_close((uv_handle_t*) &conn->io, on_udp_conn_closed);
    uv_timer_stop(&conn->timer);
}

void close_udp_remote(remote_ctx_t* ctx)
{
    if (ctx->u.nconns == 0) {
        /* there is no connection under this udp remote, free it. */
        free_udp_remote(ctx);
    } else {
        /* mark peer has been closed. */
        ctx->u.peer = NULL;
    }
}

static void on_udp_remote_read(uv_udp_t* io, ssize_t nread, const uv_buf_t* buf,
        const struct sockaddr* addr, unsigned int flags)
{
    udp_conn_t* conn = io->data;
    io_buf_t* iob = xcontainer_of(buf->base - sizeof(udp_cmd_t) - conn->alen,
        io_buf_t, buffer);

    if (nread >= 0) {
        udp_cmd_t* cmd = (udp_cmd_t*) iob->buffer;
        peer_ctx_t* peer = conn->parent->u.peer;
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from udp remote (%s), forward.",
            nread, addr_to_str(addr));

        if (!peer) {
            /* original peer has been closed, choose an available one 
             * from current session. 
             */
            udp_sess_t* sess = conn->parent->u.parent;

            if (xlist_empty(&sess->rctxs)) {
                xlog_debug("no avaliable peer, drop this udp packet.");
                xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
                return;
            }
            /* choose the last one. */
            peer = ((remote_ctx_t*) xlist_back(&sess->rctxs))->u.peer;
        }

        uv_timer_again(&conn->timer);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &peer->io) > MAX_WQUEUE_SIZE) {
            xlog_debug("peer write queue pending, drop this udp packet.");
            xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
            return;
        }

        cmd->tag = CMD_TAG;
        cmd->alen = conn->alen;
        cmd->id = conn->id;
        cmd->len = htonl(conn->alen + nread);

        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in* d = (const struct sockaddr_in*) addr;
            cmd->dport = d->sin_port;
            memcpy(cmd->data, &d->sin_addr, 4);
        } else { /* AF_INET6 */
            const struct sockaddr_in6* d = (const struct sockaddr_in6*) addr;
            cmd->dport = d->sin6_port;
            memcpy(cmd->data, &d->sin6_addr, 16);
        }

        wbuf.base = iob->buffer;
        wbuf.len = sizeof(udp_cmd_t) + conn->alen + nread;
        iob->wreq.data = peer;

        remote.crypto.encrypt(&conn->parent->u.edctx, (u8_t*) wbuf.base, wbuf.len);
        uv_write(&iob->wreq, (uv_stream_t*) &peer->io, &wbuf, 1, on_peer_write);

        /* 'iob' free later. */
    } else {
        xlog_warn("udp remote read failed: %s.", uv_err_name((int) nread));
        close_udp_conn(conn);
        /* free 'iob' now. */
        xlist_erase(&remote.io_buffers, xlist_value_iter(iob));
    }
}

static void on_udp_conn_timeout(uv_timer_t* timer)
{
    xlog_debug("udp connection (%x) timeout.", ((udp_conn_t*) timer->data)->id);
    close_udp_conn(timer->data);
}

static void on_udp_remote_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&remote.io_buffers);
    udp_conn_t* conn = handle->data;

    /* leave 'sizeof(udp_cmd_t) + conn->alen' bytes space at the beginnig.  */
    buf->base = iob->buffer + conn->alen + sizeof(udp_cmd_t);
    buf->len = MAX_SOCKBUF_SIZE - sizeof(udp_cmd_t) - conn->alen;
}

static void send_udp_packet(remote_ctx_t* ctx, udp_cmd_t* cmd, u32_t dlen)
{
    union {
        struct sockaddr     vx;
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } addr;
    uv_buf_t wbuf;
    udp_conn_t* conn;
    int error;

    if (cmd->alen == 4) {
        if (dlen < 4) {
            xlog_warn("udp packet datalen < 4.");
            return;
        }
        addr.v4.sin_family = AF_INET;
        addr.v4.sin_port = cmd->dport;
        memcpy(&addr.v4.sin_addr, cmd->data, 4);

        wbuf.base = (char*) (cmd->data + 4);
        wbuf.len = dlen - 4;
    } else { /* cmd->alen == 16 */
        if (dlen < 16) {
            xlog_warn("udp packet datalen < 16.");
            return;
        }
        addr.v6.sin6_family = AF_INET6;
        addr.v6.sin6_port = cmd->dport;
        memcpy(&addr.v6.sin6_addr, cmd->data, 16);

        wbuf.base = (char*) (cmd->data + 16);
        wbuf.len = dlen - 16;
    }
    /* 'wbuf.len' == 0 is allowed. */

    xlog_debug("%x: udp packet to %s (%d bytes).", cmd->id,
        addr_to_str(&addr), wbuf.len);

    conn = xhash_get_data(&ctx->u.parent->conns, &cmd->id);

    if (conn == XHASH_INVALID_DATA) {
        conn = xhash_iter_data(xhash_put_ex(&ctx->u.parent->conns,
                    &cmd->id, sizeof(u32_t)));

        uv_udp_init(remote.loop, &conn->io);
        uv_timer_init(remote.loop, &conn->timer);
        /* enable to send udp broadcast packet. */
        uv_udp_set_broadcast(&conn->io, 1);

        conn->alen = cmd->alen;
        conn->io.data = conn;
        conn->timer.data = conn;
        conn->parent = ctx;
        ++ctx->u.nconns;

        error = uv_udp_try_send(&conn->io, &wbuf, 1, &addr.vx);

        if (error >= 0) {
            uv_udp_recv_start(&conn->io, on_udp_remote_rbuf_alloc, on_udp_remote_read);
            uv_timer_start(&conn->timer, on_udp_conn_timeout, KEEPIDLE_TIME * 1000, 0);
        } else {
            close_udp_conn(conn);
            xlog_debug("send first udp packet failed (%s), close connection.",
                uv_err_name(error));
        }
    } else if (!uv_is_closing((uv_handle_t*) &conn->io)) {
        uv_timer_again(&conn->timer);
        error = uv_udp_try_send(&conn->io, &wbuf, 1, &addr.vx);

        if (error < 0) {
            xlog_debug("send udp packet failed: %s.", uv_err_name(error));
        }
    } else {
        xlog_debug("connection is closing, drop this packet.");
    }
}

void forward_peer_udp_packets(remote_ctx_t* ctx, u32_t nread)
{
    io_buf_t* iob = ctx->u.rbuf;
    udp_cmd_t* cmd;
    char* buf = iob->buffer + iob->idx;
    u32_t len = iob->len + nread;
    u32_t need;

    do {
        if (len <= sizeof(udp_cmd_t))
            break;
        cmd = (udp_cmd_t*) buf;
        if (cmd->tag != CMD_TAG) {
            xlog_warn("got an error udp packet (tag).");
            iob->len = 0;
            return;
        }
        need = ntohs(cmd->len) + sizeof(udp_cmd_t);
        if (need > MAX_SOCKBUF_SIZE) {
            xlog_warn("got an error udp packet (length).");
            iob->len = 0;
            return;
        }
        if (len < need)
            break;
        /* an udp packet is received completely, send out. */
        send_udp_packet(ctx, cmd, need - sizeof(udp_cmd_t));
        buf += need;
        len -= need;
    }
    while (1);

    iob->len = len;
    if (len && buf != iob->buffer) {
        memmove(iob->buffer, buf, len);
    }
}

static void on_udp_peer_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = ((peer_ctx_t*) handle->data)->remote->u.rbuf;

    buf->base = iob->buffer + iob->len;
    buf->len = MAX_SOCKBUF_SIZE - iob->len;
}

static unsigned _udp_conn_hash(void* v)
{
    return xhash_data_hash(v, sizeof(u32_t));
}

static int _udp_conn_equal(void* l, void* r)
{
    return *((u32_t*) l) == *((u32_t*) r);
}

static void connect_udp_remote(peer_ctx_t* ctx, const unsigned char* sid)
{
    udp_sess_t* sess = xhash_get_data(&remote.udp_sessions, sid);
    io_buf_t* iob = ctx->pending_iob;
    remote_ctx_t* rctx;

    if (sess == XHASH_INVALID_DATA) {
        /* the number of sessions may need to be limited, TODO. */
        sess = xhash_iter_data(xhash_put_ex(&remote.udp_sessions,
                    sid, SESSION_ID_SIZE));

        xlist_init(&sess->rctxs, sizeof(remote_ctx_t), NULL);
        xhash_init(&sess->conns, -1, sizeof(udp_conn_t),
            _udp_conn_hash, _udp_conn_equal, NULL);
    }

    rctx = xlist_alloc_back(&sess->rctxs);

    rctx->u.peer = ctx;
    rctx->u.parent = sess;
    rctx->u.rbuf = iob;
    rctx->u.nconns = 0;

    convert_nonce((u8_t*) iob->buffer);
    remote.crypto.init(&rctx->u.edctx, remote.crypto_key, (u8_t*) iob->buffer);

    ctx->remote = rctx;
    ctx->pending_iob = NULL;
    ctx->stage = STAGE_FORWARDUDP;
    /* this maybe unsafe, use 'uv_read_stop()' and 'uv_read_start()' instead? TODO. */
    ctx->io.alloc_cb = on_udp_peer_rbuf_alloc;

    if (iob->len > 0) {
        remote.crypto.decrypt(&ctx->edctx, (u8_t*) iob->buffer + iob->idx, iob->len);
        forward_peer_udp_packets(ctx->remote, 0);
    }
    iob->idx = 0;
}

int invoke_encrypted_peer_command(peer_ctx_t* ctx, io_buf_t* iob)
{
    /* process command from peer. */
    cmd_t* cmd = (cmd_t*) (iob->buffer + MAX_NONCE_LEN);

    ctx->pending_iob = iob;

    if (iob->len < CMD_MAX_SIZE + MAX_NONCE_LEN) {
        xlog_warn("got an error packet (length) from peer.");
        return -1;
    }

    remote.crypto.init(&ctx->edctx, remote.crypto_key, (u8_t*) iob->buffer);
    remote.crypto.decrypt(&ctx->edctx, (u8_t*) cmd, CMD_MAX_SIZE);

    /* pending this 'iob' always (nonce will be used when remote connected). */
    iob->idx = CMD_MAX_SIZE + MAX_NONCE_LEN;
    iob->len -= CMD_MAX_SIZE + MAX_NONCE_LEN;

    if (!is_valid_command(cmd)) {
        xlog_warn("got an error packet (header) from peer.");
        return -1;
    }

#ifdef WITH_CLIREMOTE
    if (cmd->cmd == CMD_CONNECT_CLIENT) {
        /* find an online client. */
        pending_ctx_t* pdctx = xhash_get_data(&remote.pending_ctxs, cmd->data);

        xlog_debug("got CONNECT_CLIENT cmd (%s) from peer, process.",
            devid_to_str(cmd->data));

        if (pdctx != XHASH_INVALID_DATA) {

            if (!xlist_empty(&pdctx->clients)) {
                /* online client exist, associate. */
                xlog_debug("found an available client, connect to it.");

                connect_cli_remote(ctx, xlist_front(&pdctx->clients));
                /* move client node from 'pdctx->clients' to 'remote_ctxs' */
                xlist_paste_back(&remote.remote_ctxs, xlist_cut_front(&pdctx->clients));

            } else {
                /* no online client. stop reading from peer and move it to 'pending_ctx_t'. */
                xlog_debug("no available client, pending this peer.");

                uv_read_stop((uv_stream_t*) &ctx->io);
                /* move peer node from 'peer_ctxs' to 'pdctx->peers' */
                xlist_paste_back(&pdctx->peers,
                    xlist_cut(&remote.peer_ctxs, xlist_value_iter(ctx)));

                if (!uv_is_active((uv_handle_t*) &pdctx->timer)) {
                    uv_timer_start(&pdctx->timer, on_connect_cli_remote_timeout,
                        CONNECT_CLI_TIMEO, 0);
                }
                ctx->pending_ctx = pdctx;
            }

            return 0;
        }

        xlog_warn("device_id not exist for peer.");
        return -1;
    }

    if (remote.dconnect_off) {
        xlog_debug("attempt to connect [%s] directly but function is disabled.",
            maddr_to_str(cmd));
        return -1;
    }
#endif

    if (cmd->cmd == CMD_CONNECT_IPV4) {
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = cmd->port;

        memcpy(&addr.sin_addr, cmd->data, 4);

        xlog_debug("got CONNECT_IPV4 cmd (%s) from peer, process.",
            addr_to_str(&addr));

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

        hints.ai_family = AF_UNSPEC; /* ipv4 and ipv6 */
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = 0;

        req->data = ctx;

        sprintf(portstr, "%d", ntohs(cmd->port));
        xlog_debug("got CONNECT_DOMAIN cmd (%s) from peer, process.",
            maddr_to_str(cmd));

        /* stop reading from peer until remote connected. */
        uv_read_stop((uv_stream_t*) &ctx->io);

        if (uv_getaddrinfo(remote.loop, req, on_tcp_remote_domain_resolved,
                (char*) cmd->data, portstr, &hints) == 0)
            return 0;

        xlog_error("uv_getaddrinfo (%s) failed immediately.", cmd->data);
        xlist_erase(&remote.addrinfo_reqs, xlist_value_iter(req));
        return -1;
    }

    if (cmd->cmd == CMD_CONNECT_IPV6) {
        struct sockaddr_in6 addr;

        addr.sin6_family = AF_INET6;
        addr.sin6_port = cmd->port;

        memcpy(&addr.sin6_addr, cmd->data, 16);

        xlog_debug("got CONNECT_IPV6 cmd (%s) from peer, process.",
            addr_to_str(&addr));

        /* stop reading from peer until remote connected. */
        uv_read_stop((uv_stream_t*) &ctx->io);

        if (connect_tcp_remote(ctx, (struct sockaddr*) &addr) == 0)
            return 0;

        /* connect failed immediately. */
        return -1;
    }

    if (cmd->cmd == CMD_CONNECT_UDP) {
        xlog_debug("got FORWARD_UDP cmd from peer, process.");
        connect_udp_remote(ctx, cmd->data);
        return 0;
    }

    xlog_warn("got an error command (%d) from peer.", cmd->cmd);
    return -1;
}