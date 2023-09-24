/*
 * Copyright (C) 2019-2023 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "xlist.h"

void xlist_init(xlist_t* xl, size_t val_size, xlist_destroy_cb cb)
{
    assert(val_size > 0);
    xl->size = 0;
    xl->val_size = val_size;
    xl->destroy_cb = cb;
#if XLIST_ENABLE_CACHE
    xl->cache = NULL;
#endif
    xl->head.next = &xl->head;
    xl->head.prev = &xl->head;
}

void xlist_destroy(xlist_t* xl)
{
    xlist_clear(xl);
#if XLIST_ENABLE_CACHE
    xlist_cache_free(xl);
#endif
}

xlist_t* xlist_new(size_t val_size, xlist_destroy_cb cb)
{
    xlist_t* xl = malloc(sizeof(xlist_t));

    if (xl) {
        xlist_init(xl, val_size, cb);
    }
    return xl;
}

void xlist_free(xlist_t* xl)
{
    if (xl) {
        xlist_clear(xl);
#if XLIST_ENABLE_CACHE
        xlist_cache_free(xl);
#endif
        free(xl);
    }
}

void xlist_clear(xlist_t* xl)
{
    xlist_iter_t curr = xlist_begin(xl);
    xlist_iter_t next;

    if (curr == xlist_end(xl)) {
        return;
    }
    xlist_rbegin(xl)->next = NULL;
    do {
        next = curr->next;
        if (xl->destroy_cb) {
            xl->destroy_cb(xlist_iter_value(curr));
        }
#if XLIST_ENABLE_CACHE
        curr->next = xl->cache;
        xl->cache = curr;
#else
        free(curr);
#endif
        curr = next;
    }
    while (curr);

    xl->size = 0;
    xl->head.next = &xl->head;
    xl->head.prev = &xl->head;
}

xlist_iter_t xlist_insert(xlist_t* xl, xlist_iter_t iter, const void* pvalue)
{
    xlist_iter_t newi;

#if XLIST_ENABLE_CACHE
    if (xl->cache) {
        newi = xl->cache;
        xl->cache = newi->next;
    } else {
#endif
        newi = malloc(sizeof(xlist_node_t) + xl->val_size);
        if (!newi) {
            return NULL;
        }
#if XLIST_ENABLE_CACHE
    }
#endif

    newi->next = iter;
    newi->prev = iter->prev;
    iter->prev->next = newi;
    iter->prev = newi;

    if (pvalue) {
        memcpy(xlist_iter_value(newi), pvalue, xl->val_size);
    }
    ++xl->size;
    return newi;
}

xlist_iter_t xlist_erase(xlist_t* xl, xlist_iter_t iter)
{
    xlist_iter_t r = iter->next;

    iter->prev->next = iter->next;
    iter->next->prev = iter->prev;

    if (xl->destroy_cb) {
        xl->destroy_cb(xlist_iter_value(iter));
    }
#if XLIST_ENABLE_CACHE
    iter->next = xl->cache;
    xl->cache = iter;
#else
    free(iter);
#endif

    --xl->size;
    return r;
}

#if XLIST_ENABLE_CACHE
void xlist_cache_free(xlist_t* xl)
{
    xlist_node_t* c = xl->cache;

    while (c) {
        xl->cache = c->next;
        free(c);
        c = xl->cache;
    }
}
#endif // XLIST_ENABLE_CACHE

#if XLIST_ENABLE_SORT
static xlist_node_t* __merge_list(xlist_compare_cb cmp,
        xlist_node_t* a, xlist_node_t* b)
{
    xlist_node_t* head;
    xlist_iter_t* tail = &head;

    /* merge list <a> and <b> */
    while (1) {
        if (cmp(xlist_iter_value(a),
                xlist_iter_value(b)) <= 0) {
            *tail = a;
            tail = &a->next;
            a = a->next;
            if (!a) {
                *tail = b;
                break;
            }
        } else {
            *tail = b;
            tail = &b->next;
            b = b->next;
            if (!b) {
                *tail = a;
                break;
            }
        }
    }

    return head;
}

/* refer to Linux kernel source lib/list_sort.c:
 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/lib/list_sort.c
 */
void xlist_msort(xlist_t* xl, xlist_compare_cb cmp)
{
    xlist_node_t* list = xlist_begin(xl);
    xlist_node_t* pending = NULL;
    xlist_node_t* temp;

    size_t count = 0;
    size_t bits;

    /* less than 2 nodes */
    if (list == xlist_rbegin(xl)) {
        return;
    }

    assert(cmp != NULL);
    xlist_rbegin(xl)->next = NULL;

    do {
        /* move one node from <list> to <pending> */
        list->prev = pending;
        pending = list;
        list = list->next;
        pending->next = NULL;

        for (bits = count++; bits & 1; bits >>= 1) {
            /* merge the last 2 pending lists */
            temp = __merge_list(cmp, pending, pending->prev);
            temp->prev = pending->prev->prev;
            pending = temp;
        }
    }
    while (list);

    /* merge the rest of pending lists */
    list = pending;
    while (pending->prev) {
        list = __merge_list(cmp, list, pending->prev);
        pending = pending->prev;
    }

    temp = &xl->head;
    temp->next = list;

    /* rebuild <prev> links */
    do {
        list->prev = temp;
        temp = list;
        list = list->next;
    }
    while (list);

    xl->head.prev = temp;
    temp->next = &xl->head;
}
#endif // XLIST_ENABLE_SORT

#if XLIST_ENABLE_CUT
void xlist_cut_free(xlist_t* xl, void* pvalue)
{
    xlist_iter_t iter = xlist_value_iter(pvalue);

    if (xl->destroy_cb) {
        xl->destroy_cb(pvalue);
    }
// #if XLIST_ENABLE_CACHE
//     iter->next = xl->cache;
//     xl->cache = iter;
// #else
    free(iter);
// #endif
}
#endif // XLIST_ENABLE_CUT
