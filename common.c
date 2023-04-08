/*
 * Copyright (C) 2021-2023 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>
#include <stdlib.h>

#include "common.h"

static u32_t __seed;
static char __addrbuf[MAX_DOMAIN_LEN + 8]; /* long enough to store ipv4/ipv6/domain string and port. */

void seed_rand(u32_t seed)
{
    __seed = seed;
}

static u32_t rand_int()
{
    return __seed = __seed * 1103515245 + 12345;
}

void rand_bytes(u8_t* data, u32_t len)
{
    while (len >= 4) {
        *((u32_t*) data) = rand_int();

        data += 4;
        len -= 4;
    }

    if (len) {
        u32_t r = rand_int();

        switch (len) {
        case 3: *data++ = (r >> 16) & 0xff;
        case 2: *data++ = (r >>  8) & 0xff;
        case 1: *data++ = (r >>  0) & 0xff;
            break;
        }
    }
}

int parse_ip_str(const char* str, int port, struct sockaddr* addr)
{
    const char* p;
    int len;

    if (str[0] != '[') {
        /* "ipv4addr:port". */
        char tmp[16];

        p = strchr(str, ':');

        if (p) {
            /* with 'port'. */
            port = atoi(p + 1);
            len = (int) (p - str);
        } else {
            /* without 'port. */
            len = (int) strlen(str);
        }

        if (port <= 0 || len > sizeof(tmp) - 1)
            return -1;

        if (len) {
            /* with 'ipv4addr'. */
            memcpy(tmp, str, len);
            tmp[len] = 0;
        } else {
            /* without 'ipv4addr'. */
            strcpy(tmp, "127.0.0.1");
        }

        return uv_ip4_addr(tmp, port, (struct sockaddr_in*) addr);

    } else {
        /* "[ipv6addr]:port". */
        char tmp[46];

        p = strchr(str, ']');

        if (!p) return -1;

        if (p[1] == ':') {
            /* with 'port'. */
            port = atoi(p + 2);
        }

        len = (int) (p - str - 1); /* 'ipv6addr' length */

        if (port <= 0 || len > sizeof(tmp) - 1)
            return -1;

        if (len > 0) {
            /* with 'ipv6addr'. */
            memcpy(tmp, str + 1, len);
            tmp[len] = 0;
        } else {
            /* without 'ipv6addr'. */
            strcpy(tmp, "::1");
        }

        return uv_ip6_addr(tmp, port, (struct sockaddr_in6*) addr);
    }
}

int parse_domain_str(const char* str, int port, struct sockaddr_dm* addr)
{
    /* validate domain, TODO. */
    const char* p = strchr(str, ':');
    int len;

    if (p) {
        port = atoi(p + 1);
        len = (int) (p - str);
    } else {
        len = (int) strlen(str);
    }

    if (port <= 0 || len > MAX_DOMAIN_LEN - 1)
        return -1;

    addr->sdm_family = 0;
    addr->sdm_port = htons(port);

    if (len) {
        memcpy(addr->sdm_addr, str, len);
        addr->sdm_addr[len] = 0;
    } else {
        strcpy(addr->sdm_addr, "localhost");
    }

    return 0;
}

int resolve_domain_sync(uv_loop_t* loop,
        const struct sockaddr_dm* dm, struct sockaddr* addr)
{
    struct addrinfo hints;
    char portstr[8];
    uv_getaddrinfo_t req;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC; /* ipv4 and ipv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    sprintf(portstr, "%d", ntohs(dm->sdm_port));

    if (uv_getaddrinfo(loop, &req, NULL,
            (char*) dm->sdm_addr, portstr, &hints) != 0)
        return -1;

    /* get first result only. */
    memcpy(addr, req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);

    uv_freeaddrinfo(req.addrinfo);
    return 0;
}

const char* addr_to_str(const void* addr)
{
    union {
        const struct sockaddr*     dx;
        const struct sockaddr_in*  d4;
        const struct sockaddr_in6* d6;
        const struct sockaddr_dm*  dm;
    } u = { addr };

    switch (u.dx->sa_family) {
    case AF_INET:
        uv_inet_ntop(AF_INET, &u.d4->sin_addr, __addrbuf, sizeof(__addrbuf));
        sprintf(__addrbuf + strlen(__addrbuf), ":%d", ntohs(u.d4->sin_port));
        break;

    case AF_INET6:
        uv_inet_ntop(AF_INET6, &u.d6->sin6_addr, __addrbuf, sizeof(__addrbuf));
        sprintf(__addrbuf + strlen(__addrbuf), ":%d", ntohs(u.d6->sin6_port));
        break;

    case 0: /* domain */
        sprintf(__addrbuf, "%s:%d", u.dm->sdm_addr, ntohs(u.dm->sdm_port));
        break;

    default:
        strcpy(__addrbuf, "unkown-addr-type");
        break;
    }

    return __addrbuf;
}

const char* maddr_to_str(const cmd_t* cmd)
{
    switch (cmd->cmd) {
    case CMD_CONNECT_IPV4:
        uv_inet_ntop(AF_INET, &cmd->data, __addrbuf, sizeof(__addrbuf));
        sprintf(__addrbuf + strlen(__addrbuf), ":%d", ntohs(cmd->port));
        break;

    case CMD_CONNECT_IPV6:
        uv_inet_ntop(AF_INET6, &cmd->data, __addrbuf, sizeof(__addrbuf));
        sprintf(__addrbuf + strlen(__addrbuf), ":%d", ntohs(cmd->port));
        break;

    case CMD_CONNECT_DOMAIN:
        sprintf(__addrbuf, "%s:%d", cmd->data, ntohs(cmd->port));
        break;

    case CMD_CONNECT_UDP:
        sprintf(__addrbuf, "udp-session-%x", *(u32_t*) cmd->data);
        break;

    case CMD_CONNECT_CLIENT:
    case CMD_REPORT_DEVID:
        return devid_to_str(cmd->data);

    default:
        strcpy(__addrbuf, "unkown-cmd-type");
        break;
    }

    return __addrbuf;
}

const char* devid_to_str(const u8_t id[DEVICE_ID_SIZE])
{
    __addrbuf[DEVICE_ID_SIZE] = 0;
    memcpy(__addrbuf, id, DEVICE_ID_SIZE);
    return __addrbuf;
}

int str_to_devid(u8_t id[DEVICE_ID_SIZE], const char* str)
{
    int i, l = (int) strlen(str);

    if (!l || l > DEVICE_ID_SIZE)
        return -1;

    memcpy(id, str, l);

    for (i = l; i < DEVICE_ID_SIZE; ++i) {
        id[i] = i - l;
    }

    return 0;
}

static inline void mmhash64(unsigned char h[8], const unsigned char* d, unsigned l)
{
    unsigned h1 = 0 ^ l;    /* seed ^ len */
    unsigned h2 = 0;        /* seed >> 32 */
    unsigned k1;
    unsigned k2;

    while (l >= 8) {
        k1 = d[0] | d[1] << 8 | d[2] << 16 | d[3] << 24;
        k2 = d[4] | d[5] << 8 | d[6] << 16 | d[7] << 24;

        k1 *= 0x5bd1e995;
        k1 ^= k1 >> 24;
        k1 *= 0x5bd1e995;
        h1 *= 0x5bd1e995;
        h1 ^= k1;

        k2 *= 0x5bd1e995;
        k2 ^= k2 >> 24;
        k2 *= 0x5bd1e995;
        h2 *= 0x5bd1e995;
        h2 ^= k2;

        l -= 8;
        d += 8;
    }

    if (l >= 4) {
        k1 = d[0] | d[1] << 8 | d[2] << 16 | d[3] << 24;

        k1 *= 0x5bd1e995;
        k1 ^= k1 >> 24;
        k1 *= 0x5bd1e995;
        h1 *= 0x5bd1e995;
        h1 ^= k1;

        l -= 4;
        d += 4;
    }

    switch (l) {
    case 3: h2 ^= d[2] << 16;
    case 2: h2 ^= d[1] << 8;
    case 1: h2 ^= d[0];
            h2 *= 0x5bd1e995;
    }

    h1 ^= h2 >> 18;
    h1 *= 0x5bd1e995;
    h2 ^= h1 >> 22;
    h2 *= 0x5bd1e995;
    h1 ^= h2 >> 17;
    h1 *= 0x5bd1e995;
    h2 ^= h1 >> 19;
    h2 *= 0x5bd1e995;

    h[0] = (h1 >>  0) & 0xff;
    h[1] = (h1 >>  8) & 0xff;
    h[2] = (h1 >> 16) & 0xff;
    h[3] = (h1 >> 24) & 0xff;
    h[4] = (h2 >>  0) & 0xff;
    h[5] = (h2 >>  8) & 0xff;
    h[6] = (h2 >> 16) & 0xff;
    h[7] = (h2 >> 24) & 0xff;
}

void fill_command_md(cmd_t* cmd)
{
    mmhash64(cmd->md, cmd->md + CMD_MD_SIZE, CMD_MAX_SIZE - CMD_MD_SIZE);
}

int check_command_md(cmd_t* cmd)
{
    u8_t md[CMD_MD_SIZE];

    mmhash64(md, cmd->md + CMD_MD_SIZE, CMD_MAX_SIZE - CMD_MD_SIZE);
    return memcmp(md, cmd->md, CMD_MD_SIZE) == 0;
}

const char* version_string()
{
#define __STRINGIFY_HELPER(v) #v
#define __STRINGIFY(v) __STRINGIFY_HELPER(v)

#define __VERSION_STRING __STRINGIFY(VERSION_MAJOR) \
                    "."  __STRINGIFY(VERSION_MINOR) \
                    "."  __STRINGIFY(VERSION_PATCH)

#if VERSION_ISREL
    return __VERSION_STRING "-release";
#elif defined(GIT_COMMIT_ID)
    return __VERSION_STRING "-" GIT_COMMIT_ID;
#else
    return __VERSION_STRING "-dev";
#endif
}