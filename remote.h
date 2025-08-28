/*
 * Copyright (C) 2021-2025 nonikon@qq.com.
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

typedef struct conn_stats conn_stats_t;
typedef struct peer_ctx peer_ctx_t;
typedef struct pending_ctx pending_ctx_t;
typedef struct udp_session udp_session_t;

typedef union {
#ifdef WITH_CLIREMOTE
    /* client remote */
    struct {
        peer_ctx_t* peer;
        pending_ctx_t* parent;  /* the 'pending_ctx_t' belonging to */
        uv_tcp_t io;
        crypto_ctx_t edctx;
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
        udp_session_t* parent;
        io_buf_t* last_iob;
        crypto_ctx_t edctx;
    } u;
} remote_ctx_t;

struct peer_ctx {
    uv_tcp_t io;
    remote_ctx_t* remote;
    conn_stats_t* stats;
    io_buf_t* pending_iob;      /* the pending 'io_buf_t' before 'remote' connected */
    crypto_ctx_t edctx;
    u8_t peer_blocked;
    u8_t remote_blocked;
    u8_t stage;
    u8_t nodelay;               /* TCP nodelay flag in cmd_t.flag */
    u8_t addrpref;              /* prefer addr type flag in cmd_t.flag */
};

/*  public */ void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf);
/*  public */ void on_cli_remote_connect(uv_stream_t* stream, int status);
/*  public */ void on_peer_closed(uv_handle_t* handle);
/*  public */ void on_peer_write(uv_write_t* req, int status);
/*  public */ void on_peer_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
/* virtual */ void on_peer_state_change(peer_ctx_t* ctx, int connected);

typedef struct {
    uv_loop_t* loop;
    xlist_t peer_ctxs;      /* peer_ctx_t */
    xlist_t io_buffers;     /* io_buf_t */
    xlist_t conn_reqs;      /* uv_connect_t */
    xlist_t addrinfo_reqs;  /* uv_getaddrinfo_t */
    crypto_t crypto;
    u8_t crypto_key[16];
#ifdef WITH_CLIREMOTE
    u32_t dconnect_off;
#endif
} remote_t;

extern remote_t remote;

void remote_private_init();
void remote_private_destroy();

#ifdef WITH_CTRLSERVER
int start_ctrl_server(uv_loop_t* loop, const char* addrstr);
#endif

#endif // _REMOTE_H_