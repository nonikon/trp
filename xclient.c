/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include "xclient.h"

xclient_t xclient;

void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xclient.io_buffers);

    buf->base = iob->buffer;
    buf->len = MAX_SOCKBUF_SIZE;
}

void on_io_closed(uv_handle_t* handle)
{
    xclient_ctx_t* ctx = handle->data;

    if (ctx->ref_count > 1) {
        --ctx->ref_count;
    } else {
        if (ctx->pending_iob) {
            xlist_erase(&xclient.io_buffers, xlist_value_iter(ctx->pending_iob));
        }
        xlist_erase(&xclient.xclient_ctxs, xlist_value_iter(ctx));

        xlog_debug("current %zd ctxs, %zd iobufs.",
            xlist_size(&xclient.xclient_ctxs), xlist_size(&xclient.io_buffers));
    }
}

void on_xserver_write(uv_write_t* req, int status)
{
    xclient_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xclient_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_xserver) == 0) {
        xlog_debug("proxy server write queue cleared.");

        /* proxy server write queue cleared, start reading from proxy client. */
        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_iobuf_alloc, on_xclient_read);
        ctx->xclient_blocked = 0;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xclient_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        xlog_debug("recved %zd bytes from proxy server, forward.", nread);

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        xclient.cryptox.decrypt(&ctx->dctx, (u8_t*) wbuf.base, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xclient,
            &wbuf, 1, on_xclient_write);

        if (uv_stream_get_write_queue_size(
                (uv_stream_t*) &ctx->io_xclient) > MAX_WQUEUE_SIZE) {
            xlog_debug("proxy client write queue pending.");

            /* stop reading from proxy server until proxy client write queue cleared. */
            uv_read_stop(stream);
            ctx->xserver_blocked = 1;
        }

        /* don't release 'iob' in this place,
         *'on_sclient_write' callback will do it.
         */
    } else if (nread < 0) {
        xlog_debug("disconnected from proxy server: %s.",
            uv_err_name((int) nread));

        uv_close((uv_handle_t*) stream, on_io_closed);
        uv_close((uv_handle_t*) &ctx->io_xclient, on_io_closed);

        if (buf->base) {
            /* 'buf->base' may be 'NULL' when 'nread' < 0. */
            xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
        }

    } else {
        xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
    }
}

static void on_xserver_connected(uv_connect_t* req, int status)
{
    xclient_ctx_t* ctx = req->data;

    if (status < 0) {
        xlog_error("connect proxy server failed: %s.", uv_err_name(status));

        /* 'status' will be 'ECANCELED' when 'uv_close' is called before proxy server connected.
         * as a result, we should check it to avoid calling 'uv_close' twice.
         */
        // if (status != ECANCELED) {
            uv_close((uv_handle_t*) &ctx->io_xclient, on_io_closed);
            uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        // }

    } else {
        uv_buf_t wbuf;

        xlog_debug("proxy server connected.");

        uv_read_start((uv_stream_t*) &ctx->io_xclient,
            on_iobuf_alloc, on_xclient_read);
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
        /* enable tcp-keepalive. */
        uv_tcp_keepalive(&ctx->io_xserver, 1, KEEPIDLE_TIME);

        /* send connect command. */
        wbuf.base = ctx->pending_iob->buffer;
        wbuf.len = ctx->pending_iob->len;

        uv_write(&ctx->pending_iob->wreq, (uv_stream_t*) &ctx->io_xserver,
            &wbuf, 1, on_xserver_write);

        ctx->pending_iob = NULL;
        ctx->stage = STAGE_FORWARD;
    }

    xlist_erase(&xclient.conn_reqs, xlist_value_iter(req));
}

int connect_xserver(xclient_ctx_t* ctx)
{
    uv_connect_t* req = xlist_alloc_back(&xclient.conn_reqs);

    xlog_debug("connecting porxy server [%s]...", addr_to_str(&xclient.xserver_addr));

    req->data = ctx;
    /* 'io_xserver' will be opened, increase refcount. */
    ++ctx->ref_count;

    if (uv_tcp_connect(req, &ctx->io_xserver,
            &xclient.xserver_addr.x, on_xserver_connected) != 0) {
        xlog_error("connect proxy server failed immediately.");

        uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        xlist_erase(&xclient.conn_reqs, xlist_value_iter(req));
        return -1;
    }

    ctx->stage = STAGE_CONNECT;
    return 0;
}

void on_xclient_write(uv_write_t* req, int status)
{
    xclient_ctx_t* ctx = req->data;
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (ctx->xserver_blocked && uv_stream_get_write_queue_size(
            (uv_stream_t*) &ctx->io_xclient) == 0) {
        xlog_debug("proxy client write queue cleared.");

        /* proxy client write queue cleared, start reading from proxy server. */
        uv_read_start((uv_stream_t*) &ctx->io_xserver,
            on_iobuf_alloc, on_xserver_read);
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
        rand_bytes(pbuf, MAX_NONCE_LEN);

        cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

        cmd->tag = CMD_TAG;
        cmd->major = VERSION_MAJOR;
        cmd->minor = VERSION_MINOR;
        cmd->cmd = CMD_CONNECT_CLIENT;
        cmd->len = DEVICE_ID_SIZE;

        memcpy(cmd->data, xclient.device_id, DEVICE_ID_SIZE);

        xclient.crypto.init(&ctx->ectx, xclient.crypto_key, pbuf);
        xclient.crypto.encrypt(&ctx->ectx, (u8_t*) cmd, CMD_MAX_SIZE);

        pbuf += MAX_NONCE_LEN + CMD_MAX_SIZE;
    }

    /* generate and prepend iv in the first packet */
    rand_bytes(pbuf, MAX_NONCE_LEN);

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

    xclient.cryptox.init(&ctx->ectx, xclient.cryptox_key, pbuf);
    xclient.cryptox.init(&ctx->dctx, xclient.cryptox_key, dnonce);
    xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) cmd, CMD_MAX_SIZE);

    iob->wreq.data = ctx;
    iob->len = pbuf + MAX_NONCE_LEN + CMD_MAX_SIZE - (u8_t*) iob->buffer;

    ctx->pending_iob = iob;
}