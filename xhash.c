/*
 * Copyright (C) 2019-2021 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>

#include "xhash.h"

static int buckets_expand(xhash_t* xh)
{
    size_t i;
    size_t new_sz = xh->bkt_size << 1;
    xhash_node_t** new_bkts = realloc(xh->buckets,
                        sizeof(xhash_node_t*) * new_sz);
    xhash_iter_t unlinked;
    xhash_iter_t iter;

    if (!new_bkts) return -1;

    memset(&new_bkts[xh->bkt_size], 0,
            sizeof(xhash_node_t*) * xh->bkt_size);

    /* rehash */
    for (i = 0; i < xh->bkt_size; ++i)
    {
        iter = new_bkts[i];

        while (iter)
        {
            if (iter->hash & xh->bkt_size)
            {
                /* unlink this node */
                unlinked = iter;
                iter = unlinked->next;

                if (unlinked->next)
                    unlinked->next->prev = unlinked->prev;
                if (unlinked->prev)
                    unlinked->prev->next = iter;
                else
                    new_bkts[i] = iter;

                /* insert unlinked node into buckets[i + bkt_size] */
                unlinked->prev = NULL;
                unlinked->next = new_bkts[i + xh->bkt_size];

                if (unlinked->next)
                    unlinked->next->prev = unlinked;

                new_bkts[i + xh->bkt_size] = unlinked;
            }
            else
            {
                iter = iter->next;
            }
        }
    }

    xh->bkt_size = new_sz;
    xh->buckets = new_bkts;
    return 0;
}

xhash_t* xhash_init(xhash_t* xh, int size, size_t data_size,
            xhash_hash_cb hash_cb, xhash_equal_cb equal_cb,
            xhash_destroy_cb destroy_cb)
{
    xh->hash_cb     = hash_cb;
    xh->equal_cb    = equal_cb;
    xh->destroy_cb  = destroy_cb;
    xh->bkt_size    = size > 0 ? size : XHASH_DEFAULT_SIZE;
    xh->data_size   = data_size;
    xh->size        = 0;
    xh->loadfactor  = XHASH_DEFAULT_LOADFACTOR;
#if XHASH_ENABLE_CACHE
    xh->cache       = NULL;
#endif
    /* no check 'xh->buckets' null or not */
    xh->buckets     = malloc(sizeof(xhash_node_t*) * xh->bkt_size);

    if (xh->buckets)
    {
        memset(xh->buckets, 0, sizeof(xhash_node_t*) * xh->bkt_size);
        return xh;
    }

    return NULL;
}

void xhash_destroy(xhash_t* xh)
{
    xhash_clear(xh);
#if XHASH_ENABLE_CACHE
    xhash_cache_free(xh);
#endif
    free(xh->buckets);
}

xhash_t* xhash_new(int size, size_t data_size, xhash_hash_cb hash_cb,
            xhash_equal_cb equal_cb, xhash_destroy_cb destroy_cb)
{
    xhash_t* xh = malloc(sizeof(xhash_t));

    if (xh)
    {
        if (xhash_init(xh, size, data_size,
                hash_cb, equal_cb, destroy_cb))
            return xh;
        free(xh);
    }

    return NULL;
}

void xhash_free(xhash_t* xh)
{
    if (xh)
    {
        xhash_clear(xh);
#if XHASH_ENABLE_CACHE
        xhash_cache_free(xh);
#endif
        free(xh->buckets);
        free(xh);
    }
}

xhash_iter_t xhash_put_ex(xhash_t* xh, const void* pdata, size_t ksz)
{
    unsigned hash = xh->hash_cb((void*)pdata);
    xhash_iter_t iter = xh->buckets[hash & (xh->bkt_size - 1)];
    xhash_iter_t prev = NULL;

    while (iter)
    {
        if (hash == iter->hash
            && xh->equal_cb(xhash_iter_data(iter), (void*)pdata))
        {
            return iter;
        }

        prev = iter;
        iter = iter->next;
    }

#if XHASH_ENABLE_CACHE
    if (xh->cache)
    {
        iter = xh->cache;
        xh->cache = iter->next;
    }
    else
    {
#endif
        iter = malloc(sizeof(xhash_node_t) + xh->data_size);
        if (!iter)
            return NULL;
#if XHASH_ENABLE_CACHE
    }
#endif
    memcpy(xhash_iter_data(iter), pdata, ksz);

    if (prev)
    {
        /* this bucket already has some node, append */
        prev->next = iter;
        iter->prev = prev;
    }
    else
    {
        /* this bucket has no node, assign */
        xh->buckets[hash & (xh->bkt_size - 1)] = iter;
        iter->prev = NULL;
    }

    iter->next = NULL;
    iter->hash = hash;

    ++xh->size;

    /* check loadfactor */
    if (xh->size * 100 > xh->bkt_size * xh->loadfactor)
        buckets_expand(xh);

    return iter;
}

xhash_iter_t xhash_get(xhash_t* xh, const void* pdata)
{
    unsigned hash = xh->hash_cb((void*)pdata);
    xhash_iter_t iter = xh->buckets[hash & (xh->bkt_size - 1)];

    while (iter)
    {
        if (hash == iter->hash
            && xh->equal_cb(xhash_iter_data(iter), (void*)pdata))
        {
            return iter;
        }

        iter = iter->next;
    }

    return NULL;
}

void xhash_remove(xhash_t* xh, xhash_iter_t iter)
{
    if (iter->prev)
        iter->prev->next = iter->next;
    else
        xh->buckets[iter->hash & (xh->bkt_size - 1)] = iter->next;

    if (iter->next)
        iter->next->prev = iter->prev;

    if (xh->destroy_cb)
        xh->destroy_cb(xhash_iter_data(iter));

#if XHASH_ENABLE_CACHE
    iter->next = xh->cache;
    xh->cache = iter;
#else
    free(iter);
#endif

    --xh->size;
}

void xhash_clear(xhash_t* xh)
{
    size_t i;
    xhash_node_t* curr = NULL;
    xhash_node_t* next;

    for (i = 0; i < xh->bkt_size; ++i)
    {
        curr = xh->buckets[i];

        if (!curr) continue;

        do
        {
            next = curr->next;

            if (xh->destroy_cb)
                xh->destroy_cb(xhash_iter_data(curr));
            free(curr);

            curr = next;
        }
        while (curr);

        xh->buckets[i] = NULL;
    }

    xh->size = 0;
}

#if XHASH_ENABLE_CACHE
void xhash_cache_free(xhash_t* xh)
{
    xhash_node_t* c = xh->cache;

    while (c)
    {
        xh->cache = c->next;
        free(c);
        c = xh->cache;
    }
}
#endif

xhash_iter_t xhash_begin(xhash_t* xh)
{
    size_t i;

    for (i = 0; i < xh->bkt_size; ++i)
    {
        if (xh->buckets[i])
            return xh->buckets[i];
    }

    return NULL;
}

xhash_iter_t xhash_iter_next(xhash_t* xh, xhash_iter_t iter)
{
    size_t i;

    if (iter->next)
        return iter->next;

    i = iter->hash & (xh->bkt_size - 1);

    while (++i < xh->bkt_size)
    {
        if (xh->buckets[i])
            return xh->buckets[i];
    }

    return NULL;
}