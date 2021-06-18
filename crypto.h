/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "common.h"

enum {
    CRYPTO_NONE,
    CRYPTO_CHACHA20,
    CRYPTO_SM4OFB,
};

typedef struct crypto_ctx {
    u8_t _[152]; /* MAX(sizeof(chacha20_ctx_t, sm4_ctx_t)) */
} crypto_ctx_t;

typedef struct crypto {
    int (*init)(crypto_ctx_t* ctx, const u8_t key[16], const u8_t iv[16]);
    int (*encrypt)(crypto_ctx_t* ctx, u8_t* data, u32_t len);
    int (*decrypt)(crypto_ctx_t* ctx, u8_t* data, u32_t len);
} crypto_t;

int crypto_init(crypto_t* c, int method);
void derive_key(u8_t key[16], const char* str);
void convert_nonce(u8_t nonce[16]);

#endif // _CRYPTO_H_