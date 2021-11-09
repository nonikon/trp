/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XCLIENT_H_
#define _XCLIENT_H_

#include "common.h"
#include "crypto.h"
#include "xlog.h"
#include "xlist.h"

#define KEEPIDLE_TIME       (40) /* s */

enum {
    STAGE_INIT,
    STAGE_COMMAND,
    STAGE_CONNECT, /* remote connecting */
    STAGE_FORWARD, /* remote connected */
};

typedef struct {
    uv_tcp_t io_xclient;    /* socks-client or tunnel-client */
    uv_tcp_t io_xserver;    /* proxy-server */
    io_buf_t* pending_iob;  /* dest address (connect command) */
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t ref_count;         /* increase when 'io_xserver' or 'io_xclient' opened, decrease when closed */
    u8_t xclient_blocked;
    u8_t xserver_blocked;
    u8_t stage;
} xclient_ctx_t;

/*  public */ void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf);
/*  public */ void on_io_closed(uv_handle_t* handle);

/*  public */ void on_xserver_write(uv_write_t* req, int status);
/*  public */ void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
/*  public */ void on_xclient_write(uv_write_t* req, int status);
/* virtual */ void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

/*  public */ void init_connect_command(xclient_ctx_t* ctx, u8_t code, u16_t port, u8_t* addr, u32_t addrlen);
/*  public */ int connect_xserver(xclient_ctx_t* ctx);

typedef struct {
    union {
        struct sockaddr x;
        struct sockaddr_in6 d;
    } xserver_addr;
    xlist_t xclient_ctxs;   /* xclient_ctx_t */
    xlist_t io_buffers;     /* io_buf_t */
    xlist_t conn_reqs;      /* uv_connect_t */
    crypto_t crypto;
    crypto_t cryptox;
    u8_t crypto_key[16];
    u8_t cryptox_key[16];
    u8_t device_id[DEVICE_ID_SIZE];
} xclient_t;

extern xclient_t xclient;

#endif // _XCLIENT_H_