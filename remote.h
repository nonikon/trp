/*
 * Copyright (C) 2021-2022 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _REMOTE_H_
#define _REMOTE_H_

#include "common.h"
#include "crypto.h"
#include "xlog.h"
#include "xlist.h"
#include "xhash.h"

enum {
    STAGE_INIT,
    STAGE_COMMAND,
    STAGE_CONNECT,
    STAGE_FORWARDCLI,
    STAGE_FORWARDTCP,
    STAGE_FORWARDUDP,
};

typedef struct peer_ctx peer_ctx_t;

#ifdef WITH_CLIREMOTE
typedef struct {
    u8_t devid[DEVICE_ID_SIZE]; /* (must be the first member) */
    xlist_t clients;            /* remote_ctx_t, the clients which at COMMAND stage */
    xlist_t peers;              /* peer_ctx_t, the peers which is connecting to a client */
    uv_timer_t timer;           /* peers connect timeout timer */
} pending_ctx_t;
#endif

/* [udp_sess_t]
 *   |- [remote_ctx_t]
 *   |    |- [udp_conn_t]
 *   |    |- [udp_conn_t]
 *   |    |- ...
 *   |- [remote_ctx_t]
 *   |    |- [udp_conn_t]
 *   |    |- ...
 *   | -...
 */
typedef struct {
    u8_t sid[SESSION_ID_SIZE];  /* (must be the first member) */
    xlist_t rctxs;              /* remote_ctx_t, udp remote contexts with this sid */
    xhash_t conns;              /* udp_conn_t, udp connections with this sid */
} udp_sess_t;

typedef union {
#ifdef WITH_CLIREMOTE
    /* client remote */
    struct {
        peer_ctx_t* peer;
        uv_tcp_t io;
        crypto_ctx_t edctx;
        pending_ctx_t* pending_ctx; /* the 'pending_ctx_t' belonging to */
    } c;
#endif
    /* tcp remote */
    struct {
        peer_ctx_t* peer;
        uv_tcp_t io;
        crypto_ctx_t edctx;
    } t;
    /* udp remote */
    struct {
        peer_ctx_t* peer;
        udp_sess_t* parent;
        io_buf_t* rbuf;
        crypto_ctx_t edctx;
        u32_t nconns;   /* the number of udp connections under this 'remote_ctx_t' */
    } u;
} remote_ctx_t;

typedef struct {
    u32_t id;   /* (must be the first member) */
    u8_t alen;  /* addr length */
    uv_udp_t io;
    uv_timer_t timer;
    remote_ctx_t* parent;
} udp_conn_t;

struct peer_ctx {
    uv_tcp_t io;
    remote_ctx_t* remote;
#ifdef WITH_CLIREMOTE
    pending_ctx_t* pending_ctx; /* the 'pending_ctx_t' belonging to */
#endif
    io_buf_t* pending_iob;      /* the pending 'io_buf_t' before 'remote' connected */
    crypto_ctx_t edctx;
    u8_t peer_blocked;
    u8_t remote_blocked;
    u8_t stage;
};

/*  public */ void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf);
#ifdef WITH_CLIREMOTE
/*  public */ void on_cli_remote_closed(uv_handle_t* handle);
/*  public */ void on_cli_remote_write(uv_write_t* req, int status);
/*  public */ void on_cli_remote_connect(uv_stream_t* stream, int status);
#endif
/*  public */ void on_tcp_remote_closed(uv_handle_t* handle);
/*  public */ void on_tcp_remote_write(uv_write_t* req, int status);
/*  public */ void on_peer_closed(uv_handle_t* handle);
/*  public */ void on_peer_write(uv_write_t* req, int status);
/* virtual */ void on_peer_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
/*  public */ void close_udp_remote(remote_ctx_t* ctx);
/*  public */ void forward_peer_udp_packets(remote_ctx_t* ctx, u32_t nread);
/*  public */ int invoke_encrypted_peer_command(peer_ctx_t* ctx, io_buf_t* iob);

typedef struct {
    uv_loop_t* loop;
#ifdef WITH_CLIREMOTE
    xhash_t pending_ctxs;   /* pending_ctx_t */
#endif
    xlist_t remote_ctxs;    /* remote_ctx_t */
    xlist_t peer_ctxs;      /* peer_ctx_t */
    xlist_t io_buffers;     /* io_buf_t */
    xlist_t conn_reqs;      /* uv_connect_t */
    xlist_t addrinfo_reqs;  /* uv_getaddrinfo_t */
    xhash_t udp_sessions;   /* udp_session_t */
    crypto_t crypto;
    u8_t crypto_key[16];
} remote_t;

extern remote_t remote;

#endif // _REMOTE_H_