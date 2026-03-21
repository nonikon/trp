/*
 * Copyright (C) 2021-2026 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XCLIENT_H_
#define _XCLIENT_H_

#include "common.h"
#include "crypto.h"
#include "xlog.h"
#include "xlist.h"
#include "xhash.h"

typedef struct {
    union {
        struct {
            uv_tcp_t io;    /* socks-client or tunnel-client */
        } t;
        struct {
            io_buf_t* last_iob;
            io_buf_t* pending_pkts[MAX_PENDING_UPKTS]; /* the pending udp packets before xserver connected */
            u32_t npending;
        } u;
    } peer;
    uv_tcp_t io_xserver;    /* proxy-server */
    io_buf_t* pending_iob;  /* dest address (connect command) */
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t peer_blocked;
    u8_t xserver_blocked;
    u8_t xconnected;        /* proxy-server connected (0 - connecting, 1 - connected) */
    u8_t stage;
} xclient_ctx_t;

void on_iobuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf);

void on_tcp_io_closed(uv_handle_t* handle);
void init_connect_command(xclient_ctx_t* ctx, u8_t code, u16_t port, u8_t* addr, u32_t addrlen);
void start_tcp_forward(xclient_ctx_t* ctx, int reading);
int connect_xserver(xclient_ctx_t* ctx, void* arg);

u32_t get_udp_packet_id(const struct sockaddr* saddr);
const struct sockaddr* get_udp_packet_saddr(u32_t id);
void send_udp_packet(io_buf_t* iob);
void recv_udp_packet(udp_cmd_t* cmd); /* virtual */

typedef struct {
    uv_loop_t* loop;
    union {
        struct sockaddr x;
        struct sockaddr_in6 d;
    } xserver_addr;
#ifdef __ANDROID__
    u8_t profd;             /* protect fd */
#endif
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