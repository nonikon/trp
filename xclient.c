/*
 * Copyright (C) 2021-2023 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>

#include "xclient.h"

xclient_t xclient; /* xclient public data */

typedef struct addr2id addr2id_t;
typedef struct id2addr id2addr_t;

struct addr2id {
    union {
        struct sockaddr     vx;
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } addr;            /* MUST be the first member */
    u8_t alive;
    uv_timer_t timer;
    id2addr_t* ia;
};
struct id2addr {
    u32_t id;           /* MUST be the first member */
    addr2id_t* ai;
};

/* xclient private data */
static struct {
    xhash_t addr2ids;       /* addr2id_t */
    xhash_t id2addrs;       /* id2addr_t */
    xlist_t u_xclient_ctxs; /* xclient_ctx_t */
    xlist_t conn_reqs;      /* uv_connect_t */
    u8_t session_id[SESSION_ID_SIZE];
    u32_t next_upktid;
} xclient_pri;

void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xclient.io_buffers);

    buf->base = iob->buffer;
    buf->len = MAX_SOCKBUF_SIZE;
}

void on_io_closed(uv_handle_t* handle)
{
    xclient_ctx_t* ctx = handle->data;

    if (--ctx->ref_count) return; /* ctx free later */

    if (ctx->is_udp) {
        if (ctx->xclient.u.last_iob) {
            xlist_erase(&xclient.io_buffers,
                xlist_value_iter(ctx->xclient.u.last_iob));
        }
        if (ctx->xclient.u.npending) {
            u32_t n = ctx->xclient.u.npending;
            do {
                xlist_erase(&xclient.io_buffers,
                    xlist_value_iter(ctx->xclient.u.pending_pkts[--n]));
            } while (n);
        }
    }
    if (ctx->pending_iob) {
        xlist_erase(&xclient.io_buffers, xlist_value_iter(ctx->pending_iob));
    }
    xlist_erase(&xclient.xclient_ctxs, xlist_value_iter(ctx));

    xlog_debug("current %zu ctxs, %zu iobufs.",
        xlist_size(&xclient.xclient_ctxs), xlist_size(&xclient.io_buffers));
}

void on_xserver_write(uv_write_t* req, int status)
{
    xclient_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xclient_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_xserver) == 0) {
        xlog_debug("proxy server write queue cleared.");

        /* proxy server write queue cleared, start reading from proxy client. */
        uv_read_start((uv_stream_t*) &ctx->xclient.t.io, on_iobuf_alloc, on_xclient_read);
        ctx->xclient_blocked = 0;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
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

static int forward_xserver_udp_packets(xclient_ctx_t* ctx, io_buf_t* iob)
{
    udp_cmd_t* cmd;
    u32_t need;

    if (ctx->xclient.u.last_iob) {
        io_buf_t* last_iob = ctx->xclient.u.last_iob;

        /* 'last_iob->idx' is always zero. */
        if (last_iob->len < sizeof(udp_cmd_t)
                && __iob_move(last_iob, iob, sizeof(udp_cmd_t)) != 0)
            return 0;

        cmd = (udp_cmd_t*) last_iob->buffer;
        need = ntohs(cmd->len) + sizeof(udp_cmd_t);

        if (need > MAX_SOCKBUF_SIZE || need < cmd->alen + 2 + sizeof(udp_cmd_t)) {
            xlog_warn("error udp packet length (%u).", need);

            ctx->xclient.u.last_iob = NULL;
            xlist_erase(&xclient.io_buffers, xlist_value_iter(last_iob));
            return 0;
        }

        if (__iob_move(last_iob, iob, need) != 0)
            return 0;

        recv_udp_packet(cmd);

        ctx->xclient.u.last_iob = NULL;
        xlist_erase(&xclient.io_buffers, xlist_value_iter(last_iob));
    }

    while (iob->len > sizeof(udp_cmd_t)) {
        cmd = (udp_cmd_t*) (iob->buffer + iob->idx);
        need = ntohs(cmd->len) + sizeof(udp_cmd_t);

        if (need > MAX_SOCKBUF_SIZE || need < cmd->alen + 2 + sizeof(udp_cmd_t)) {
            xlog_warn("error udp packet length (%u).", need);
            return 0;
        }
        if (iob->len < need) {
            /* udp packet need more. */
            break;
        }
        recv_udp_packet(cmd);

        iob->idx += need;
        iob->len -= need;
    }

    if (iob->len) {
        if (iob->idx) {
            memmove(iob->buffer, iob->buffer + iob->idx, iob->len);
            iob->idx = 0;
        }
        xlog_debug("%u udp bytes left.", iob->len);

        ctx->xclient.u.last_iob = iob;
        return 1;
    }

    return 0;
}

static inline void close_xclient(xclient_ctx_t* ctx)
{
    uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
    if (!ctx->is_udp) {
        uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
    } else {
        /* move 'ctx' node from 'u_xclient_ctxs' to 'xclient_ctxs'. */
        xlist_paste_back(&xclient.xclient_ctxs,
            xlist_cut(&xclient_pri.u_xclient_ctxs, xlist_value_iter(ctx)));
    }
}

void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xclient_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        xclient.cryptox.decrypt(&ctx->dctx, (u8_t*) buf->base, (u32_t) nread);

        if (!ctx->is_udp) {
            uv_buf_t wbuf;
            xlog_debug("%zd tcp bytes from proxy server.", nread);

            wbuf.base = buf->base;
            wbuf.len = nread;

            iob->wreq.data = ctx;
            uv_write(&iob->wreq, (uv_stream_t*) &ctx->xclient.t.io,
                &wbuf, 1, on_xclient_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->xclient.t.io) > MAX_WQUEUE_SIZE) {
                xlog_debug("proxy client write queue pending.");

                /* stop reading from proxy server until proxy client write queue cleared. */
                uv_read_stop(stream);
                ctx->xserver_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }
        /* ctx->is_udp */
        xlog_debug("%zd udp bytes from proxy server.", nread);

        iob->idx = 0;
        iob->len = (u32_t) nread;

        if (forward_xserver_udp_packets(ctx, iob) != 0) {
            /* some bytes left, 'iob' free later. */
            return;
        }

    } else if (nread < 0) {
        xlog_debug("disconnected from proxy server: %s.", uv_err_name((int) nread));

        close_xclient(ctx);
        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

static void on_xserver_connected(uv_connect_t* req, int status)
{
    xclient_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_warn("connect proxy server failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before proxy server connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            close_xclient(ctx);
        // }
    } else {
        uv_buf_t wbuf;

        xlog_debug("proxy server connected.");

        /* send connect command. */
        wbuf.base = ctx->pending_iob->buffer;
        wbuf.len = ctx->pending_iob->len;

        uv_write(&ctx->pending_iob->wreq, (uv_stream_t*) &ctx->io_xserver,
            &wbuf, 1, on_xserver_write);

        ctx->pending_iob = NULL;
        ctx->stage = STAGE_FORWARD;

        /* enable tcp-keepalive. */
        // uv_tcp_keepalive(&ctx->io_xserver, 1, KEEPIDLE_TIME);

        uv_read_start((uv_stream_t*) &ctx->io_xserver, on_iobuf_alloc, on_xserver_read);

        if (!ctx->is_udp) {
            uv_read_start((uv_stream_t*) &ctx->xclient.t.io, on_iobuf_alloc,
                on_xclient_read);

        } else if (ctx->xclient.u.npending) {
            u32_t i = 0;

            xlog_debug("write %d pending udp packets.", ctx->xclient.u.npending);
            /* write pending udp packets one by one. */
            do {
                io_buf_t* iob = ctx->xclient.u.pending_pkts[i++];

                wbuf.base = iob->buffer;
                wbuf.len = iob->len;

                iob->wreq.data = ctx;
                uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver, &wbuf, 1,
                    on_xserver_write);
            } while (i < ctx->xclient.u.npending);

            ctx->xclient.u.npending = 0;
        }
    }

    xlist_erase(&xclient_pri.conn_reqs, xlist_value_iter(req));
}

int connect_xserver(xclient_ctx_t* ctx)
{
    uv_connect_t* req = xlist_alloc_back(&xclient_pri.conn_reqs);

    xlog_debug("connecting porxy server [%s]...", addr_to_str(&xclient.xserver_addr));
    req->data = ctx;

    if (uv_tcp_connect(req, &ctx->io_xserver, &xclient.xserver_addr.x,
            on_xserver_connected) == 0) {
        ctx->stage = STAGE_CONNECT;
        return 0;
    }
    xlog_warn("connect proxy server failed immediately.");

    xlist_erase(&xclient_pri.conn_reqs, xlist_value_iter(req));
    return -1;
}

void on_xclient_write(uv_write_t* req, int status)
{
    xclient_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xserver_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->xclient.t.io) == 0) {
        xlog_debug("proxy client write queue cleared.");

        /* proxy client write queue cleared, start reading from proxy server. */
        uv_read_start((uv_stream_t*) &ctx->io_xserver, on_iobuf_alloc, on_xserver_read);
        ctx->xserver_blocked = 0;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

void init_connect_command(xclient_ctx_t* ctx,
                u8_t code, u16_t port, u8_t* addr, u32_t addrlen)
{
    io_buf_t* iob = xlist_alloc_back(&xclient.io_buffers);
    u8_t* pbuf = (u8_t*) iob->buffer;
    cmd_t* cmd;
    u8_t dnonce[16];

    if (is_valid_devid(xclient.device_id)) {
        /* generate and prepend iv in the first packet */
        generate_nonce(pbuf);

        cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

        cmd->tag = CMD_TAG;
        cmd->major = VERSION_MAJOR;
        cmd->minor = VERSION_MINOR;
        cmd->cmd = CMD_CONNECT_CLIENT;
        cmd->len = DEVICE_ID_SIZE;

        memcpy(cmd->data, xclient.device_id, DEVICE_ID_SIZE);

        fill_command_md(cmd);
        xclient.crypto.init(&ctx->ectx, xclient.crypto_key, pbuf);
        xclient.crypto.encrypt(&ctx->ectx, (u8_t*) cmd, CMD_MAX_SIZE);

        pbuf += MAX_NONCE_LEN + CMD_MAX_SIZE;
    }

    /* generate and prepend iv in the first packet */
    generate_nonce(pbuf);

    cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

    cmd->tag = CMD_TAG;
    cmd->major = VERSION_MAJOR;
    cmd->minor = VERSION_MINOR;
    cmd->cmd = code;
    cmd->len = (u8_t) addrlen;
    cmd->port = port;

    memcpy(cmd->data, addr, addrlen);

    xlog_debug("proxy to [%s].", maddr_to_str(cmd));

    memcpy(dnonce, pbuf, MAX_NONCE_LEN);
    convert_nonce(dnonce);

    fill_command_md(cmd);
    xclient.cryptox.init(&ctx->ectx, xclient.cryptox_key, pbuf);
    xclient.cryptox.init(&ctx->dctx, xclient.cryptox_key, dnonce);
    xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) cmd, CMD_MAX_SIZE);

    iob->wreq.data = ctx;
    iob->len = pbuf + MAX_NONCE_LEN + CMD_MAX_SIZE - (u8_t*) iob->buffer;

    ctx->pending_iob = iob;
}

static void on_udp_packet_id_free(uv_handle_t* handle)
{
    addr2id_t* ai = handle->data;

    xlog_debug("free udp packet id %x, %zd left.", ai->ia->id,
        xhash_size(&xclient_pri.id2addrs) - 1);
    xhash_remove_data(&xclient_pri.id2addrs, ai->ia);
    xhash_remove_data(&xclient_pri.addr2ids, ai);
}

static void on_udp_packet_id_check(uv_timer_t* timer)
{
    addr2id_t* ai = timer->data;

    if (!ai->alive)
        uv_close((uv_handle_t*) timer, on_udp_packet_id_free);
    else
        ai->alive = 0;
}

u32_t get_udp_packet_id(const struct sockaddr* saddr)
{
    addr2id_t* ai = xhash_get_data(&xclient_pri.addr2ids, saddr);

    if (ai != XHASH_INVALID_DATA) {
        ai->alive = 1;
        return ai->ia->id;
    }
    xlog_debug("new udp packet id %x.", xclient_pri.next_upktid);

    ai = xhash_iter_data(xhash_put_ex(&xclient_pri.addr2ids,
            saddr, sizeof(ai->addr))); /* 'sizeof(ai->addr)' mybe unsafe in the future, TODO. */

    uv_timer_init(xclient.loop, &ai->timer);
    /* check if this id is still alive every 'xclient.utimeo' seconds. */
    uv_timer_start(&ai->timer, on_udp_packet_id_check, xclient.utimeo * 1000,
        xclient.utimeo * 1000);

    ai->timer.data = ai;
    ai->alive = 0;
    ai->ia = xhash_iter_data(xhash_put_ex(&xclient_pri.id2addrs,
                &xclient_pri.next_upktid, 4));
    ai->ia->ai = ai;

    return xclient_pri.next_upktid++;
}

const struct sockaddr* get_udp_packet_saddr(u32_t id)
{
    id2addr_t* ia = xhash_get_data(&xclient_pri.id2addrs, &id);

    if (ia != XHASH_INVALID_DATA) {
        ia->ai->alive = 1;
        return &ia->ai->addr.vx;
    }
    return NULL;
}

void send_udp_packet(io_buf_t* iob)
{
    static xlist_iter_t iter; /* the 'xclient_ctx_t' used for next udp packet. */
    xclient_ctx_t* ctx;

    if (xlist_size(&xclient_pri.u_xclient_ctxs) < xclient.n_uconnect) {
        ctx = xlist_alloc_back(&xclient.xclient_ctxs);

        uv_tcp_init(xclient.loop, &ctx->io_xserver);

        ctx->xclient.u.last_iob = NULL;
        ctx->xclient.u.pending_pkts[0] = iob;
        ctx->xclient.u.npending = 1;
        ctx->io_xserver.data = ctx;
        ctx->ref_count = 1;
        ctx->is_udp = 1;
        ctx->xclient_blocked = 0;
        ctx->xserver_blocked = 0;
        ctx->stage = STAGE_INIT;

        init_connect_command(ctx, CMD_CONNECT_UDP, 0, xclient_pri.session_id,
            SESSION_ID_SIZE);
        xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) iob->buffer, iob->len);

        if (connect_xserver(ctx) == 0) {
            /* move 'ctx' node from 'xclient_ctxs' to 'u_xclient_ctxs'. */
            xlist_paste_front(&xclient_pri.u_xclient_ctxs,
                xlist_cut(&xclient.xclient_ctxs, xlist_value_iter(ctx)));
            iter = xlist_value_iter(ctx);
        } else {
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        }
    } else {
        ctx = xlist_iter_value(iter); /* 'iter' is always valid */
        xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) iob->buffer, iob->len);

        if (ctx->stage != STAGE_CONNECT) {
            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_xserver) <= MAX_WQUEUE_SIZE) {
                uv_buf_t wbuf;

                wbuf.base = iob->buffer;
                wbuf.len = iob->len;

                iob->wreq.data = ctx;
                uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver, &wbuf, 1,
                    on_xserver_write);
            } else {
                xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
                xlog_debug("proxy server write queue pending, drop this udp packet.");
            }

        } else if (ctx->xclient.u.npending < MAX_PENDING_UPKTS) {
            ctx->xclient.u.pending_pkts[ctx->xclient.u.npending++] = iob;
            xlog_debug("pending this udp packet (%d/%d).", ctx->xclient.u.npending,
                MAX_PENDING_UPKTS);

        } else {
            xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
            xlog_debug("pending queue full, drop this udp packet.");
        }

        iter = xlist_iter_valid(&xclient_pri.u_xclient_ctxs, xlist_iter_next(iter))
                    ? xlist_iter_next(iter) : xlist_begin(&xclient_pri.u_xclient_ctxs);
    }
}

static inline unsigned __addr_hash(const u8_t* addr, u16_t port, u16_t len)
{
    unsigned h = (len << 16) | port, k;

    while (len >= 4) {
        k = addr[0] | addr[1] << 8 |
            addr[2] << 16 | addr[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        addr += 4;
        len -= 4;
    }

    /* 'len' is always 0. */
#if 0
    switch (len) {
    case 3:
        h ^= addr[2] << 16; /* fall through */
    case 2:
        h ^= addr[1] << 8;  /* fall through */
    case 1:
        h ^= addr[0];
        h *= 0x5bd1e995;
    }
#endif

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}

static unsigned __addr2id_hash(void* _v)
{
    addr2id_t* v = _v;

    switch (v->addr.vx.sa_family) {
    case AF_INET:
        return __addr_hash((u8_t*) &v->addr.v4.sin_addr, v->addr.v4.sin_port, 4);
    default: /* AF_INET6 */
        return __addr_hash((u8_t*) &v->addr.v6.sin6_addr, v->addr.v6.sin6_port, 16);
    }
}
static int __addr2id_equal(void* _l, void* _r)
{
    addr2id_t* l = _l;
    addr2id_t* r = _r;

    if (l->addr.vx.sa_family != r->addr.vx.sa_family)
        return 0;

    switch (l->addr.vx.sa_family) {
    case AF_INET:
        return l->addr.v4.sin_port == r->addr.v4.sin_port
            && !memcmp(&l->addr.v4.sin_addr, &r->addr.v4.sin_addr, 4);
    default: /* AF_INET6 */
        return l->addr.v6.sin6_port == r->addr.v6.sin6_port
            && !memcmp(&l->addr.v6.sin6_addr, &r->addr.v6.sin6_addr, 16);
    }
}

static unsigned __id2addr_hash(void* _v)
{
    return *(u32_t*) _v;
}
static int __id2addr_equal(void* _l, void* _r)
{
    return *(u32_t*) _l == *(u32_t*) _r;
}

void xclient_private_init()
{
    xhash_init(&xclient_pri.addr2ids, -1, sizeof(addr2id_t),
        __addr2id_hash, __addr2id_equal, NULL);
    xhash_init(&xclient_pri.id2addrs, -1, sizeof(id2addr_t),
        __id2addr_hash, __id2addr_equal, NULL);
    xlist_init(&xclient_pri.u_xclient_ctxs, sizeof(xclient_ctx_t), NULL);
    xlist_init(&xclient_pri.conn_reqs, sizeof(uv_connect_t), NULL);

    if (uv_random(NULL, NULL, xclient_pri.session_id, SESSION_ID_SIZE, 0, NULL) != 0) {
        xlog_warn("uv_random failed, use default random.");
        rand_bytes(xclient_pri.session_id, SESSION_ID_SIZE);
    }
    rand_bytes((u8_t*) &xclient_pri.next_upktid, 4);
}

void xclient_private_destroy()
{
    xlist_destroy(&xclient_pri.conn_reqs);
    xlist_destroy(&xclient_pri.u_xclient_ctxs);
    xhash_destroy(&xclient_pri.id2addrs);
    xhash_destroy(&xclient_pri.addr2ids);
}