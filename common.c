/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>
#include <stdlib.h>

#include "common.h"

static u32_t _seed;
static char _addrbuf[MAX_DOMAIN_LEN + 8]; /* long enough to store ipv4/ipv6/domain string and port. */

void seed_rand(u32_t seed)
{
    _seed = seed;
}

static u32_t rand_int()
{
    return _seed = _seed * 1103515245 + 12345;
}

void rand_bytes(u8_t* data, u32_t len)
{
    while (len >= 4) {
        *((u32_t*) data) = rand_int();

        data += 4;
        len -= 4;
    }

    while (len--) {
        *data++ = (u8_t) rand_int();
    }
}

int parse_ip4_str(const char* str, int defport, struct sockaddr_in* addr)
{
    char* p = strchr(str, ':');

    if (p) {
        char ip[16];

        if (p - str > 15)
            return -1;

        if (p == str)
            return uv_ip4_addr("127.0.0.1", atoi(p + 1), addr);

        memcpy(ip, str, p - str);
        ip[p - str] = 0;

        return uv_ip4_addr(ip, atoi(p + 1), addr);
    }

    if (defport < 0) return -1;

    return uv_ip4_addr(str, defport, addr);
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
            len = p - str;
        } else {
            /* without 'port. */
            len = strlen(str);
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

        len = p - str - 1; /* 'ipv6addr' length */

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
        len = p - str;
    } else {
        len = strlen(str);
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

const char* addr_to_str(const void* addr)
{
    union {
        const struct sockaddr*     d;
        const struct sockaddr_in*  d4;
        const struct sockaddr_in6* d6;
        const struct sockaddr_dm*  dm;
    } u;

    _addrbuf[0] = 0;
    u.d = addr;

    switch (u.d->sa_family) {
    case AF_INET:
        uv_inet_ntop(AF_INET, &u.d4->sin_addr, _addrbuf, sizeof(_addrbuf));
        sprintf(_addrbuf + strlen(_addrbuf), ":%d", ntohs(u.d4->sin_port));
        break;

    case AF_INET6:
        uv_inet_ntop(AF_INET6, &u.d6->sin6_addr, _addrbuf, sizeof(_addrbuf));
        sprintf(_addrbuf + strlen(_addrbuf), ":%d", ntohs(u.d6->sin6_port));
        break;

    case 0: /* domain */
        sprintf(_addrbuf, "%s:%d", u.dm->sdm_addr, ntohs(u.dm->sdm_port));
        break;
    }

    return _addrbuf;
}

const char* maddr_to_str(const cmd_t* cmd)
{
    _addrbuf[0] = 0;

    switch (cmd->cmd) {
    case CMD_CONNECT_IPV4:
        uv_inet_ntop(AF_INET, &cmd->t.addr, _addrbuf, sizeof(_addrbuf));
        sprintf(_addrbuf + strlen(_addrbuf), ":%d", ntohs(cmd->t.port));
        break;

    case CMD_CONNECT_IPV6:
        uv_inet_ntop(AF_INET6, &cmd->t.addr, _addrbuf, sizeof(_addrbuf));
        sprintf(_addrbuf + strlen(_addrbuf), ":%d", ntohs(cmd->t.port));
        break;

    case CMD_CONNECT_DOMAIN:
        sprintf(_addrbuf, "%s:%d", cmd->t.addr, ntohs(cmd->t.port));
        break;

    case CMD_CONNECT_CLIENT:
        return devid_to_str(cmd->d.devid);
    }

    return _addrbuf;
}

const char* devid_to_str(const u8_t id[DEVICE_ID_SIZE])
{
    static const char tb[16] = "0123456789ABCDEF";
    static char buf[DEVICE_ID_SIZE * 2 + 1];
    int i;

    for (i = 0; i < DEVICE_ID_SIZE; ++i) {
        buf[i * 2] = tb[id[i] >> 4];
        buf[i * 2 + 1] = tb[id[i] & 0x0F];
    }

    return buf;
}

int str_to_devid(u8_t id[DEVICE_ID_SIZE], const char* str)
{
    int i, c;

    if (strlen(str) != DEVICE_ID_SIZE * 2)
        return -1;
    
    for (i = 0; i < DEVICE_ID_SIZE * 2; ++i) {

        if (str[i] >= '0' && str[i] <= '9')
            c = str[i] - '0';
        else if (str[i] >= 'a' && str[i] <= 'f')
            c = str[i] - 'a' + 10;
        else if (str[i] >= 'A' && str[i] <= 'F')
            c = str[i] - 'A' + 10;
        else
            return -1;

        id[i / 2] = id[i / 2] << 4 | c;
    }

    return is_valid_devid(id) ? 0 : -1;
}