/*
 * Copyright (C) 2021-2025 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <uv.h>

#define xcontainer_of(ptr, type, member) \
            ((type*) ((char*) (ptr) - offsetof(type, member)))

#define VERSION_MAJOR       1
#define VERSION_MINOR       4
#define VERSION_PATCH       4
#define VERSION_ISREL       1

#define DEF_CONFIG_FILE     "trp.ini"
#define DEF_DEVID_STRING    "test"

#define DEF_SERVER_PORT     9901    /* default server port */
#define DEF_XSERVER_PORT    9902    /* default proxy server port */
#define DEF_CSERVER_PORT    9903    /* default control server (http) port */
#define DEF_TSERVER_PORT    8800    /* default tunnel server port */
#define DEF_SSERVER_PORT    8801    /* default socks proxy port */
#define LISTEN_BACKLOG      1024

#define MAX_NONCE_LEN       16
#define MAX_DOMAIN_LEN      64
#define MAX_PENDING_UPKTS   16
#define MAX_UDPCONN_TIMEO   40      /* s */
#define MAX_WQUEUE_SIZE     0       /* bytes */
#define MAX_SOCKBUF_SIZE    (8192 - sizeof(io_buf_t) - sizeof(xlist_node_t))

#define SESSION_ID_SIZE     16      /* proxy-client session id size */
#define DEVICE_ID_SIZE      16      /* client device id size, MUST <= MAX_DOMAIN_LEN */

#define RECSRV_INTVL_MIN    (10)    /* min reconnect interval time */
#define RECSRV_INTVL_MAX    (600)   /* max reconnect interval time */
#define RECSRV_INTVL_STEP   (10)    /* increase reconnect interval time after connect failed */

#define CONNECT_CLI_TIMEO   (10)    /* s */
#define UDPCONN_TIMEO       (20)    /* s */
#define KEEPIDLE_TIME       (40)    /* s */

typedef unsigned char   u8_t;
typedef signed char     s8_t;
typedef unsigned short  u16_t;
typedef signed short    s16_t;
typedef unsigned int    u32_t;
typedef signed int      s32_t;

enum {
    CMD_CONNECT_IPV4,   /* [4] */
    CMD_CONNECT_IPV6,   /* [16] */
    CMD_CONNECT_DOMAIN, /* [n] */
    CMD_CONNECT_CLIENT, /* [DEVICE_ID_SIZE] */
    CMD_CONNECT_UDP,    /* [SESSION_ID_SIZE] */
    CMD_REPORT_DEVID,   /* [DEVICE_ID_SIZE] */
};

enum {
    FLG_ADDRPREF_NONE,
    FLG_ADDRPREF_IPV4,
    FLG_ADDRPREF_IPV6,
};

#define CMD_TAG         0x7E
#define CMD_MD_SIZE     8
#define CMD_MAX_SIZE    (sizeof(cmd_t) + MAX_DOMAIN_LEN)

typedef struct {
    u8_t md[CMD_MD_SIZE]; /* digest of cmd_t (MUST be the first member) */

    u8_t tag;   /* CMD_TAG */
    u8_t major; /* VERSION_MAJOR */
    u8_t minor; /* VERSION_MINOR */
    u8_t flag;  /* 1 bit TCP nodelay flag, 2 bits FLG_ADDRPREF_* flag */
    u8_t cmd;   /* CMD_CONNECT_IPV4, ... */
    u8_t len;   /* data length */
    u16_t port; /* big endian port */
    u8_t data[0];
} cmd_t;

typedef struct {
    u8_t flag;      /* 1 bit CLOSE_ON_RECV flag, 7 bits UDP connection timeout (seconds) */
    u8_t alen;      /* daddr length */
    u16_t len;      /* data length (daddr + dport + payload) */
    u32_t id;       /* packet id (source address) */
    u8_t data[0];   /* daddr + dport + payload */
} udp_cmd_t;

typedef struct {
    u32_t idx;
    u32_t len;
    uv_write_t wreq;
    char buffer[0];
} io_buf_t;

typedef struct {
    char* name;
    char* value;
    char buffer[0];
} config_item_t;

/* domain struct which compatible with 'struct sockaddr' */
struct sockaddr_dm {
    u16_t sdm_family; /* (always '0') */
    u16_t sdm_port;   /* big endian port */
     char sdm_addr[MAX_DOMAIN_LEN]; /* null-terminated domain */
};

static inline int is_valid_devid(const u8_t* s) {
    return s[0];
}

static inline int is_valid_command(const cmd_t* c) {
    return c->tag == CMD_TAG
        && c->major == VERSION_MAJOR
        && c->minor == VERSION_MINOR;
}

#ifdef _WIN32
int daemon(int argc, char** argv);
#endif

void seed_rand(u32_t seed);
void rand_bytes(u8_t* data, u32_t len);

/* parse config path string. Eg:
 * - "file:section" -> [file], [section]
 * - ":section" -> [DEF_CONFIG_FILE], [section]
 * - "file" -> [file], [sec]
 * - NULL -> [DEF_CONFIG_FILE], [sec]
 * NOTE: content of '*str' may be modified.
 */
void parse_config_str(char** str, const char** sec);

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
/* ... */
const char* devid_to_str(const u8_t id[DEVICE_ID_SIZE]);
/* ... */
int str_to_devid(u8_t id[DEVICE_ID_SIZE], const char* str);

/* load config file from 'path' with section 'sec'. */
int load_config_file(const char* path, const char* sec);
/* get the next config item. */
config_item_t* get_config_item(config_item_t* prev);

/* fill 'cmd->md'. */
void fill_command_md(cmd_t* cmd);
/* validate 'cmd->md'. */
int check_command_md(cmd_t* cmd);

/* get current version string. */
const char* version_string();

#endif // _COMMON_H_