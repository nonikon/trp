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
#define VERSION_MINOR       0x02

#define DEF_SERVER_PORT     9901    /* default server port */
#define DEF_XSERVER_PORT    9902    /* default proxy server port */
#define DEF_CSERVER_PORT    9903    /* default control server (http) port */
#define DEF_TSERVER_PORT    8800    /* default tunnel server port */
#define DEF_SSERVER_PORT    8801    /* default socks5 proxy port */
#define LISTEN_BACKLOG      1024

#define MAX_NONCE_LEN       16
#define MAX_IPADDR_LEN      16
#define MAX_DOMAIN_LEN      64
#define MAX_SOCKBUF_SIZE    4096
#define MAX_WQUEUE_SIZE     0 /* bytes */

#define DEVICE_ID_SIZE      8

typedef unsigned char   u8_t;
typedef signed char     s8_t;
typedef unsigned short  u16_t;
typedef signed short    s16_t;
typedef unsigned int    u32_t;
typedef signed int      s32_t;

enum {
    CMD_CONNECT_IPV4,
    CMD_CONNECT_IPV6,   /* current not supported */
    CMD_CONNECT_DOMAIN, /* current not supported */
    CMD_CONNECT_CLIENT,
    CMD_REPORT_DEVID,

    CMD_LIMIT_MAX,
};

#define CMD_TAG         0x7E

typedef struct {
    u8_t tag;
    u8_t major;
    u8_t minor;
    u8_t cmd;

    union {
        /* CMD_CONNECT_IPV4 | CMD_CONNECT_IPV6 */
        struct {
            u16_t resv; /* reserved */
            u16_t port; /* big endian */
            u8_t addr[MAX_IPADDR_LEN];
        } i;
        /* CMD_CONNECT_DOMAIN */
        struct {
            u16_t resv; /* reserved */
            u16_t port; /* big endian */
            u8_t domain[MAX_DOMAIN_LEN];
        } m;
        /* CMD_CONNECT_CLIENT | CMD_REPORT_DEVID */
        struct {
            u8_t devid[DEVICE_ID_SIZE];
        } d;
    };
} cmd_t;

#define is_valid_devid(s)   (*(u32_t*) (s))

#define is_valid_cmd(c)     ( \
            (c)->tag == CMD_TAG && \
            (c)->major == VERSION_MAJOR && \
            (c)->minor == VERSION_MINOR && \
            (c)->cmd < CMD_LIMIT_MAX)

void seed_rand(u32_t seed);
void rand_bytes(u8_t* data, u32_t len);

/* parse ipv4 string to sockaddr_in. Eg:
 * - [1.2.3.4:8080] -> [1.2.3.4], [8080]
 * - [:8080] -> [127.0.0.1], [8080]
 * - [1.2.3.4] -> [1.2.3.4], [defport]
 */
int parse_ip4_str(const char* str, int defport, struct sockaddr_in* addr);

const char* devid_to_str(u8_t id[DEVICE_ID_SIZE]);
int str_to_devid(u8_t id[DEVICE_ID_SIZE], const char* str);

#endif // _COMMON_H_