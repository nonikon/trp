/*
 * Copyright (C) 2021-2025 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XCLIENT_H_
#define _XCLIENT_H_

#include "common.h"
#include "crypto.h"
#include "xlog.h"
#include "xlist.h"
#include "xhash.h"

enum {
    STAGE_INIT,
    STAGE_COMMAND,
    STAGE_CONNECT,
    STAGE_FORWARD,
    STAGE_NOOP,
};

typedef struct {
    union {
        struct {
            uv_tcp_t io;    /* socks-client or tunnel-client */
        } t;
        struct {
            io_buf_t* last_iob;
            io_buf_t* pending_pkts[MAX_PENDING_UPKTS];
                            /* pending udp packets before xserver connected */
            u32_t npending;
        } u;
    } xclient;
    uv_tcp_t io_xserver;    /* proxy-server */
    io_buf_t* pending_iob;  /* dest address (connect command) */
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t is_udp;
    u8_t xclient_blocked;
    u8_t xserver_blocked;
    u8_t ref_count;
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

/*  public */ u32_t get_udp_packet_id(const struct sockaddr* saddr);
/*  public */ const struct sockaddr* get_udp_packet_saddr(u32_t id);
/*  public */ void send_udp_packet(io_buf_t* iob);
/* virtual */ void recv_udp_packet(udp_cmd_t* cmd);

typedef struct {
    uv_loop_t* loop;
    union {
        struct sockaddr x;
        struct sockaddr_in6 d;
    } xserver_addr;
    u8_t nodelay;           /* TCP nodelay */
    u8_t addrpref;          /* prefer addr type used in remote domain resolution */
    u8_t uclrcv;            /* udp close-on-recv */
    u8_t utimeo;            /* udp connection timeout (seconds) */
    u32_t n_uconnect;       /* max udp-over-tcp connection size */
    xlist_t xclient_ctxs;   /* xclient_ctx_t */
    xlist_t io_buffers;     /* io_buf_t */
    crypto_t crypto;
    crypto_t cryptox;
    u8_t crypto_key[16];
    u8_t cryptox_key[16];
    u8_t device_id[DEVICE_ID_SIZE];
} xclient_t;

extern xclient_t xclient;

void xclient_private_init();
void xclient_private_destroy();

#endif // _XCLIENT_H_