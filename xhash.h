/*
 * Copyright (C) 2019-2022 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XHASH_H_
#define _XHASH_H_

#include <stddef.h>

/* Hash table, logic based on java hash table. */

#ifdef HAVE_XCONFIG_H
#include "xconfig.h"
#else

/* cache can decrease memory allocation. node will be put into cache
 * when it being erased, and next insertion will pop one node from
 * cache. define 'XHASH_ENABLE_CACHE=1' to enable it. */
#ifndef XHASH_ENABLE_CACHE
#define XHASH_ENABLE_CACHE          0
#endif

#ifndef XHASH_DEFAULT_SIZE
#define XHASH_DEFAULT_SIZE          64 // MUST be 2^n
#endif

#ifndef XHASH_DEFAULT_LOADFACTOR
#define XHASH_DEFAULT_LOADFACTOR    75 // percent
#endif

#endif

typedef struct xhash        xhash_t;
typedef struct xhash_node   xhash_node_t;
typedef struct xhash_node*  xhash_iter_t;

typedef void        (*xhash_destroy_cb)(void* pdata);
typedef unsigned    (*xhash_hash_cb)(void* pdata);
typedef int         (*xhash_equal_cb)(void* l, void* r);

struct xhash_node
{
    struct xhash_node*  prev;
    struct xhash_node*  next;
    unsigned            hash;
    // char data[0];
};

struct xhash
{
    xhash_hash_cb       hash_cb;
    xhash_equal_cb      equal_cb;
    xhash_destroy_cb    destroy_cb;
    size_t              bkt_size;   // buckets size
    size_t              data_size;
    size_t              size;       // element (node) count
    size_t              loadfactor;
#if XHASH_ENABLE_CACHE
    xhash_node_t*       cache;      // cache nodes
#endif
    xhash_node_t**      buckets;
};

/* initialize a 'xhash_t'.
 * 'size' is the init bucket size, MUST be 2^n or -1 (means default).
 * 'hash_cb' is used to get hash code of an element, can't be 'NULL'.
 * 'equal_cb' is used to check the equals of two elements, can't be 'NULL'.
 * 'destroy_cb' is called when destroying an element, can be 'NULL'. */
xhash_t* xhash_init(xhash_t* xh, int size, size_t data_size,
            xhash_hash_cb hash_cb, xhash_equal_cb equal_cb, xhash_destroy_cb destroy_cb);
/* destroy a 'xhash_t' which has called 'xhash_init'. */
void xhash_destroy(xhash_t* xh);

/* allocate memory and initialize a 'xhash_t'. */
xhash_t* xhash_new(int size, size_t data_size, xhash_hash_cb hash_cb,
            xhash_equal_cb equal_cb, xhash_destroy_cb destroy_cb);
/* release memory for a 'xhash_t' which 'xhash_new' returns. */
void xhash_free(xhash_t* xh);

#if XHASH_ENABLE_CACHE
/* free all cache nodes in a 'xhash_t'. */
void xhash_cache_free(xhash_t* xh);
#endif

/* set loadfactor of 'xh', 'factor' is an interger which
 * standfor loadfactor percent. */
#define xhash_set_loadfactor(xh, factor) \
                        (xh)->loadfactor = factor

/* return the number of elements. */
#define xhash_size(xh)  ((xh)->size)
/* check whether the container is empty. */
#define xhash_empty(xh) ((xh)->size == 0)
/* return an iterator to the end. */
#define xhash_end(xh)   NULL

/* return an iterator to the beginning. */
xhash_iter_t xhash_begin(xhash_t* xh);
/* return the next iterator of 'iter'. */
xhash_iter_t xhash_iter_next(xhash_t* xh, xhash_iter_t iter);

/* check whether an iterator is valid. */
#define xhash_iter_valid(iter)  ((iter) != NULL)
/* return a pointer pointed to the data of 'iter', 'iter' MUST be valid. */
#define xhash_iter_data(iter)   ((void*)((iter) + 1))
/* return an iterator of an element data. */
#define xhash_data_iter(pdata)  ((xhash_iter_t)(pdata) - 1)

/* insert an element with specific data, return an iterator to
 * the inserted element, return 'NULL' when out of memory.
 * if the data is already exist, do nothing an return it's iterator. */
#define xhash_put(xh, pdata)    xhash_put_ex(xh, pdata, (xh)->data_size)
/* similar to 'xhash_put', but useful when we don't want to init all 'data_size',
 * just init the <key> (which size is 'ksz'), and set <value> by yourself later. */
xhash_iter_t xhash_put_ex(xhash_t* xh, const void* pdata, size_t ksz);
/* find an element with specific data. return an iterator to
 * the element with specific data, return 'NULL' if not found. */
xhash_iter_t xhash_get(xhash_t* xh, const void* pdata);
/* remove an element at 'iter', 'iter' MUST be valid. */
void xhash_remove(xhash_t* xh, xhash_iter_t iter);
/* remove all elements (no cache) in 'xh'. */
void xhash_clear(xhash_t* xh);

/* find an element with specific data. return a pointer to the element
 * with specific data, return 'XHASH_INVALID_DATA' if not found.
 * the return value can call 'xhash_data_iter' to get it's iterator. */
#define xhash_get_data(xh, pdata) \
                xhash_iter_data(xhash_get(xh, pdata))
/* remove an element, 'pdata' should be the return value of 'xhash_get_data'
 * and not equal to 'XHASH_INVALID_DATA'. */
#define xhash_remove_data(xh, pdata) \
                xhash_remove(xh, xhash_data_iter(pdata))

#define XHASH_INVALID_DATA  xhash_iter_data((xhash_iter_t)0)

/* Some helper hash function, can be used in 'xhash_hash_cb'. */

/* Aim to protect against poor hash functions by adding logic here
 * - logic taken from java 1.4 hashtable source. */
static inline unsigned xhash_improve_hash(unsigned h)
{
    h += ~(h << 9);
    h ^= ((h >> 14) | (h << 18)); /* >>> */
    h += (h << 4);
    h ^= ((h >> 10) | (h << 22)); /* >>> */
    return h;
}

#if 0
/* Basic string hash function, from Java standard String.hashCode(). */
static inline unsigned xhash_string_hash(const char* s)
{
    unsigned h = 0;
    int m = 1;
    while (*s)
    {
        h += (*s++) * m;
        m = (m << 5) - 1; /* m *= 31 */
    }
    return h;
}
#else
/* Basic string hash function, from Python's str.__hash__(). */
static inline unsigned xhash_string_hash(const char *s)
{
    const unsigned char *cp = (const unsigned char *)s;
    unsigned h = *cp << 7;
    while (*cp)
        h = (1000003 * h) ^ *cp++;
    /* This conversion truncates the length of the string, but that's ok. */
    h ^= (unsigned)(cp - (const unsigned char *)s);
    return h;
}
#endif

/* Basic data hash function, from MurmurHash2. */
static inline unsigned xhash_data_hash(const unsigned char *data, unsigned len)
{
    unsigned h = 0 ^ len, k; /* h = seed ^ len */

    while (len >= 4)
    {
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

    switch (len)
    {
    case 3:
        h ^= data[2] << 16; /* fall through */
    case 2:
        h ^= data[1] << 8;  /* fall through */
    case 1:
        h ^= data[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}

#endif // _XHASH_H_
