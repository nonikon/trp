/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <uv.h>

#define xcontainer_of(ptr, type, member) \
            ((type*) ((char*) (ptr) - offsetof(type, member)))

#define VERSION_MAJOR       0x01
#define VERSION_MINOR       0x03
#define VERSION_PATCH       0x00

#define DEF_SERVER_PORT     9901    /* default server port */
#define DEF_XSERVER_PORT    9902    /* default proxy server port */
#define DEF_CSERVER_PORT    9903    /* default control server (http) port */
#define DEF_TSERVER_PORT    8800    /* default tunnel server port */
#define DEF_SSERVER_PORT    8801    /* default socks proxy port */
#define LISTEN_BACKLOG      1024

#define MAX_NONCE_LEN       16
#define MAX_DOMAIN_LEN      64
#define MAX_WQUEUE_SIZE     0       /* bytes */
#define MAX_SOCKBUF_SIZE    (4096 - sizeof(io_buf_t) - sizeof(xlist_node_t))

#define DEVICE_ID_SIZE      8

typedef unsigned char   u8_t;
typedef signed char     s8_t;
typedef unsigned short  u16_t;
typedef signed short    s16_t;
typedef unsigned int    u32_t;
typedef signed int      s32_t;

enum {
    CMD_CONNECT_IPV4,
    CMD_CONNECT_IPV6,
    CMD_CONNECT_DOMAIN,
    CMD_CONNECT_CLIENT,
    CMD_CONNECT_UDP,
    CMD_REPORT_DEVID,
};

#define CMD_TAG         0x7E
#define CMD_MAX_SIZE    (sizeof(cmd_t) + MAX_DOMAIN_LEN)

typedef struct {
    u8_t tag;
    u8_t major;
    u8_t minor;
    u8_t cmd;
    u8_t rsv;   /* reserved */
    u8_t len;   /* data length */
    u16_t port; /* big endian port */
    u8_t data[0];
} cmd_t;

typedef struct {
    u8_t tag;
    u8_t isv6;      /* ipv6 addr flag */
    u16_t id;
    u16_t len;      /* data length */
    u16_t dport;    /* big endian dest port */
    u8_t data[0];   /* daddr + payload */
} udp_cmd_t;

/* domain struct which compatible with 'struct sockaddr' */
struct sockaddr_dm {
    u16_t sdm_family; /* (always '0') */
    u16_t sdm_port;   /* big endian port */
     char sdm_addr[MAX_DOMAIN_LEN]; /* null-terminated domain */
};

typedef struct {
    u32_t idx;
    u32_t len;
    uv_write_t wreq;
    char buffer[0];
} io_buf_t;

#define is_valid_devid(s)   (*(u32_t*) (s))

#define is_valid_command(c)     ( \
            (c)->major == VERSION_MAJOR && \
            (c)->minor == VERSION_MINOR && \
            (c)->tag == CMD_TAG)

void seed_rand(u32_t seed);
void rand_bytes(u8_t* data, u32_t len);

/* parse ipv4/ipv6 address string to 'struct sockaddr'. Eg:
 * - "1.2.3.4:8080" -> [1.2.3.4], [8080]
 * - ":8080" -> [127.0.0.1], [8080]
 * - "1.2.3.4" -> [1.2.3.4], [port]
 * - "[::]:8080" -> [::], [8080]
 * - "[]:8080" -> [::1], [8080]
 * - "[::]" -> [::], [port]
 */
int parse_ip_str(const char* str, int port, struct sockaddr* addr);

/* parse domain address string to 'struct sockaddr_dm'. Eg:
 * - "www.example.com:8080" -> [www.example.com], [8080]
 * - ":8080" -> [localhost], [8080]
 * - "www.example.com" -> [www.example.com], [port]
 */
int parse_domain_str(const char* str, int port, struct sockaddr_dm* addr);

/* resolve domain synchronously. */
int resolve_domain_sync(uv_loop_t* loop,
        const struct sockaddr_dm* dm, struct sockaddr* addr);

/* convert 'struct sockaddr' to string (include port). */
const char* addr_to_str(const void* addr);

/* convert 'cmd_t' address to string (include port). */
const char* maddr_to_str(const cmd_t* cmd);

const char* devid_to_str(const u8_t id[DEVICE_ID_SIZE]);

int str_to_devid(u8_t id[DEVICE_ID_SIZE], const char* str);

#endif // _COMMON_H_