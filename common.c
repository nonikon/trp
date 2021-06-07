/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>
#include <stdlib.h>

#include "common.h"

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

const char* devid_to_str(u8_t id[DEVICE_ID_SIZE])
{
    static const char t[16] = "0123456789ABCDEF";
    static char s[DEVICE_ID_SIZE * 2 + 1];
    int i;

    for (i = 0; i < DEVICE_ID_SIZE; ++i) {
        s[i * 2] = t[id[i] >> 4];
        s[i * 2 + 1] = t[id[i] & 0x0F];
    }

    return s;
}

int str_to_devid(u8_t id[DEVICE_ID_SIZE], const char* str)
{
    int i, c;

    if (strlen(str) != DEVICE_ID_SIZE * 2)
        return -1;
    
    for (i = 0; i < DEVICE_ID_SIZE * 2; ++i) {

        if (str[i] >= '0' && str[i] <= '9')
            c = str[i] - '0';
        else if (str[i] >= 'a' && str[i] <= 'z')
            c = str[i] - 'a';
        else if (str[i] >= 'A' && str[i] <= 'Z')
            c = str[i] - 'A';
        else
            return -1;

        id[i / 2] = id[i / 2] << 4 | c;
    }

    return is_valid_devid(id) ? 0 : -1;
}