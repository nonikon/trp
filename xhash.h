/*
 * Copyright (C) 2019-2023 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XHASH_H_
#define _XHASH_H_

#include <stddef.h>
#include <assert.h>

/* Hash table, logic based on java hash table. */

#ifdef HAVE_XCONFIG_H
#include "xconfig.h"
#endif

/* cache can decrease memory allocation. node will be put into cache
 * when it being erased, and next insertion will pop one node from
 * cache. define 'XHASH_ENABLE_CACHE=1' to enable it.
 */
#ifndef XHASH_ENABLE_CACHE
#define XHASH_ENABLE_CACHE  0
#endif

/* minimal bucket size, MUST be 2^N */
#ifndef XHASH_MINIMAL_SIZE
#define XHASH_MINIMAL_SIZE  64
#endif

/* loadfactor percent */
#ifndef XHASH_LOADFACTOR
#define XHASH_LOADFACTOR    75
#endif

typedef struct xhash xhash_t;
typedef struct xhash_node xhash_node_t;
typedef struct xhash_node* xhash_iter_t;

typedef void (*xhash_destroy_cb)(void* pdata);
typedef unsigned (*xhash_hash_cb)(void* pdata);
typedef int (*xhash_equal_cb)(void* l, void* r);

struct xhash_node {
    struct xhash_node* prev;
    struct xhash_node* next;
    unsigned hash;
    // char data[0];
};

struct xhash {
    xhash_hash_cb hash_cb;
    xhash_equal_cb equal_cb;
    xhash_destroy_cb destroy_cb;
    size_t bkt_size;
    size_t data_size;
    size_t size;
#if XHASH_ENABLE_CACHE
    xhash_node_t* cache; /* cache nodes */
#endif
    xhash_node_t** buckets;
};

/* <bkt_size> is the init bucket size, can be <= 0 (means default).
 * <hash_cb> is used to get hash code of an element, can't be <NULL>.
 * <equal_cb> is used to check the equals of two elements, can't be <NULL>.
 * <destroy_cb> is called when destroying an element, can be <NULL>.
 */
xhash_t* xhash_init(xhash_t* xh, int bkt_size, size_t data_size,
            xhash_hash_cb hash_cb, xhash_equal_cb equal_cb, xhash_destroy_cb destroy_cb);

/* <xh> must be a pointer returned by <xhash_init>. */
void xhash_destroy(xhash_t* xh);

/* similar to <xhast_init>. */
xhash_t* xhash_new(int bkt_size, size_t data_size, xhash_hash_cb hash_cb,
            xhash_equal_cb equal_cb, xhash_destroy_cb destroy_cb);

/* <xh> must be a pointer returned by <xhash_new>. */
void xhash_free(xhash_t* xh);

#if XHASH_ENABLE_CACHE
/* free all cache nodes. */
void xhash_cache_free(xhash_t* xh);
#endif

static inline size_t xhash_size(xhash_t* xh) {
    return xh->size;
}

static inline int xhash_empty(xhash_t* xh) {
    return xh->size == 0;
}

static inline xhash_iter_t xhash_end(xhash_t* xh) {
    return NULL;
}

/* return an iterator to the beginning. */
xhash_iter_t xhash_begin(xhash_t* xh);

/* return the next iterator of <iter>. */
xhash_iter_t xhash_iter_next(xhash_t* xh, xhash_iter_t iter);

/* check whether an iterator is valid. */
static inline int xhash_iter_valid(xhash_iter_t iter) {
    return iter != NULL;
}

/* return a pointer pointed to the data of <iter>, <iter> MUST be valid. */
static inline void* xhash_iter_data(xhash_iter_t iter) {
    return (void*) (iter + 1);
}

/* return an iterator of an element data. */
static inline xhash_iter_t xhash_data_iter(void* pdata) {
    return (xhash_iter_t) (pdata) - 1;
}

/* similar to <xhash_put>, but useful when we don't want to init all <data_size>,
 * just init the key (which size is <ksz>), and set <value> by yourself later.
 */
xhash_iter_t xhash_put_ex(xhash_t* xh, const void* pdata, size_t ksz);

/* insert an element with specific data, return an iterator to
 * the inserted element, return <NULL> when out of memory.
 * if the data is already exist, do nothing an return it's iterator.
 */
static inline xhash_iter_t xhash_put(xhash_t* xh, const void* pdata) {
    return xhash_put_ex(xh, pdata, xh->data_size);
}

/* find an element with specific data. return an iterator to
 * the element with specific data, return <NULL> if not found.
 */
xhash_iter_t xhash_get(xhash_t* xh, const void* pdata);

/* remove an element at <iter>, <iter> MUST be valid. */
void xhash_remove(xhash_t* xh, xhash_iter_t iter);

/* remove all elements (no cache). */
void xhash_clear(xhash_t* xh);

/* find an element with specific data. return a pointer to the element
 * with specific data, return <XHASH_INVALID_DATA> if not found.
 * the return value can call <xhash_data_iter> to get it's iterator.
 */
static inline void* xhash_get_data(xhash_t* xh, const void* pdata) {
    return xhash_iter_data(xhash_get(xh, pdata));
}

/* remove an element, <pdata> should be the return value of <xhash_get_data>
 * and not equal to <XHASH_INVALID_DATA>.
 */
static inline void xhash_remove_data(xhash_t* xh, const void* pdata) {
    xhash_remove(xh, xhash_data_iter((void*) pdata));
}

#define XHASH_INVALID_DATA ((void*) sizeof(xhash_node_t))

/* Some helper hash function, can be used in <xhash_hash_cb>. */

/* Aim to protect against poor hash functions by adding logic here
 * - logic taken from java 1.4 hashtable source.
 */
static inline unsigned xhash_improve_hash(unsigned h) {
    h += ~(h << 9);
    h ^= ((h >> 14) | (h << 18)); /* >>> */
    h += (h << 4);
    h ^= ((h >> 10) | (h << 22)); /* >>> */
    return h;
}

#if 0
/* Basic string hash function, from Java standard String.hashCode(). */
static inline unsigned xhash_string_hash(const char* s) {
    unsigned h = 0;
    int m = 1;
    while (*s) {
        h += (*s++) * m;
        m = (m << 5) - 1; /* m *= 31 */
    }
    return h;
}
#else
/* Basic string hash function, from Python's str.__hash__(). */
static inline unsigned xhash_string_hash(const char* s) {
    const unsigned char* cp = (const unsigned char*) s;
    unsigned h = *cp << 7;
    while (*cp) {
        h = (1000003 * h) ^ *cp++;
    }
    /* This conversion truncates the length of the string, but that's ok. */
    h ^= (unsigned) (cp - (const unsigned char*) s);
    return h;
}
#endif

/* Basic data hash function, from MurmurHash2. */
static inline unsigned xhash_data_hash(const unsigned char* data, unsigned len) {
    unsigned h = 0 ^ len, k; /* h = seed ^ len */
    while (len >= 4) {
        k = data[0] | data[1] << 8 |
            data[2] << 16 | data[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;
        h *= 0x5bd1e995;
        h ^= k;

        data += 4;
        len -= 4;
    }
    switch (len) {
    case 3: h ^= data[2] << 16; /* fall through */
    case 2: h ^= data[1] << 8;  /* fall through */
    case 1: h ^= data[0];
            h *= 0x5bd1e995;
    }
    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;
    return h;
}

#endif // _XHASH_H_
