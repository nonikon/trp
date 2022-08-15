/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <string.h>

#include "sm4.h"
#include "chacha.h"
#include "crypto.h"

typedef struct chacha20_ctx {
    u32_t state[16];
    chacha_buf kstream;
    u32_t idx;
} chacha20_ctx_t;

typedef struct sm4_ctx {
    SM4_KEY ks;
    u8_t iv[16];
    u32_t idx;
} sm4_ctx_t;

/* expand key from 16 bytes to 32 bytes */
static void key_expand(u8_t key[32])
{
    // TODO
    int i;
    for (i = 0; i < 16; ++i) {
        key[i + 16] = ~key[i];
    }
}

static int chacha20_ctx_init(crypto_ctx_t* _, const u8_t key[16], const u8_t iv[16])
{
    chacha20_ctx_t* ctx = (chacha20_ctx_t*) _;

    /* chacha20 constants - the string "expand 32-byte k" */
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;

    /* set key */
    memcpy(ctx->state + 4, key, 16);
    key_expand((u8_t*) (ctx->state + 4));

    /* set counter and nonce */
    memcpy(ctx->state + 12, iv, 16);

    memset(&ctx->kstream, 0, sizeof(ctx->kstream));
    ctx->idx = 0;

    return 0;
}

static int chacha20_crypt(crypto_ctx_t* _, u8_t* data, u32_t len)
{
    chacha20_ctx_t* ctx = (chacha20_ctx_t*) _;
    u32_t i = ctx->idx;

    while (i && len) {
        *data++ ^= ctx->kstream.c[i];
        --len;
        i = (i + 1) & 0x3f;
    }

    while (len >= 64) {
        chacha20_core(&ctx->kstream, ctx->state);
        ++ctx->state[12]; /* ++counter */

        for (; i < 64 / sizeof(size_t); ++i)
            ((size_t*) data)[i] ^= ((size_t*) &ctx->kstream)[i];

        len -= 64;
        data += 64;
        i = 0;
    }

    if (len) {
        chacha20_core(&ctx->kstream, ctx->state);
        ++ctx->state[12];

        while (len--) {
            data[i] ^= ctx->kstream.c[i];
            ++i;
        }
    }

    ctx->idx = i;
    return len;
}

static int sm4_ctx_init(crypto_ctx_t* _, const u8_t key[16], const u8_t iv[16])
{
    sm4_ctx_t* ctx = (sm4_ctx_t*) _;

    SM4_set_key(key, &ctx->ks);
    memcpy(ctx->iv, iv, 16);

    ctx->idx = 0;
    return 0;
}

static int sm4ofb_crypt(crypto_ctx_t* _, u8_t* data, u32_t len)
{
    sm4_ctx_t* ctx = (sm4_ctx_t*) _;
    u32_t i = ctx->idx;

    while (i && len) {
        *data++ ^= ctx->iv[i];
        --len;
        i = (i + 1) & 0xf;
    }

    while (len >= 16) {
        SM4_encrypt(ctx->iv, ctx->iv, &ctx->ks);

        for (; i < 16 / sizeof(size_t); ++i)
            ((size_t*) data)[i] ^= ((size_t*) ctx->iv)[i];

        len -= 16;
        data += 16;
        i = 0;
    }

    if (len) {
        SM4_encrypt(ctx->iv, ctx->iv, &ctx->ks);

        while (len--) {
            data[i] ^= ctx->iv[i];
            ++i;
        }
    }

    ctx->idx = i;
    return len;
}

static int dummy_ctx_init(crypto_ctx_t* _, const u8_t key[16], const u8_t iv[16])
{
    return 0;
}

static int dummy_crypt(crypto_ctx_t* _, u8_t* data, u32_t len)
{
    return len;
}

int crypto_init(crypto_t* c, int method)
{
    switch (method) {
    case CRYPTO_CHACHA20:
        c->init = chacha20_ctx_init;
        c->encrypt = chacha20_crypt;
        c->decrypt = chacha20_crypt;
        return 0;

    case CRYPTO_SM4OFB:
        c->init = sm4_ctx_init;
        c->encrypt = sm4ofb_crypt;
        c->decrypt = sm4ofb_crypt;
        return 0;

    case CRYPTO_NONE:
        c->init = dummy_ctx_init;
        c->encrypt = dummy_crypt;
        c->decrypt = dummy_crypt;
        return 0;

    default:
        return -1;
    }
}

void derive_key(u8_t key[16], const char* str)
{
    // TODO, MD5?
    u32_t h = (u32_t) strlen(str);
    u32_t i;

    if (h >= 16) {
        memcpy(key, str, 16); /* truncate if > 16 */
        h = 16;
    } else {
        memcpy(key, str, h);
        memset(key + h, 0, 16 - h);
    }

    for (i = 0; i < 16; i += 4) {
        u32_t u = (key[i])
                | (key[i + 1] <<  8)
                | (key[i + 2] << 16)
                | (key[i + 3] << 24);

        h  = (u + h) * 0x41c64e6d + 0x3039;
        h += ~(h << 9);
        h ^= ((h >> 14) | (h << 18));
        h += (h << 4);
        h ^= ((h >> 10) | (h << 22));

        key[i + 0] = (h      ) & 0xff;
        key[i + 1] = (h >>  8) & 0xff;
        key[i + 2] = (h >> 16) & 0xff;
        key[i + 3] = (h >> 24) & 0xff;
    }
}

void convert_nonce(u8_t nonce[16])
{
    // TODO
    int i;
    for (i = 0; i < 16; ++i) {
        nonce[i] = ~nonce[i];
    }
}