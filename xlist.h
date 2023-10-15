/*
 * Copyright (C) 2019-2023 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XLIST_H_
#define _XLIST_H_

#include <stddef.h>

/* doubly-linked list, similar to C++ STL std::list */

#ifdef HAVE_XCONFIG_H
#include "xconfig.h"
#endif

/* cache can decrease memory allocation. node will be put into cache
 * when it being erased, and next insertion will pop one node from
 * cache. define 'XLIST_ENABLE_CACHE=1' to enable it.
 */
#ifndef XLIST_ENABLE_CACHE
#define XLIST_ENABLE_CACHE  0
#endif

/* enable xlist_msort interface or not. */
#ifndef XLIST_ENABLE_SORT
#define XLIST_ENABLE_SORT   1
#endif

/* enable xlist_cut_* interface or not. */
#ifndef XLIST_ENABLE_CUT
#define XLIST_ENABLE_CUT    1
#endif

typedef struct xlist xlist_t;
typedef struct xlist_node xlist_node_t;
typedef struct xlist_node* xlist_iter_t;

typedef void (*xlist_destroy_cb)(void* pvalue);
typedef int (*xlist_compare_cb)(void* l, void* r);

struct xlist_node {
    struct xlist_node* prev;
    struct xlist_node* next;
    // value
};

struct xlist {
    size_t size;
    size_t val_size; /* element value size in <xlist_node_t> */
    xlist_destroy_cb destroy_cb; /* called when element destroy */
#if XLIST_ENABLE_CACHE
    xlist_node_t* cache; /* cache nodes */
#endif
    xlist_node_t head;
};

/* <val_size> is the size of element value.
 * <cb> is called when element destroy, can be NULL, but it usually
 * can't be NULL when value type is a pointer or contains a pointer.
 */
void xlist_init(xlist_t* xl, size_t val_size, xlist_destroy_cb cb);

/* <xl> must be a pointer returned by <xlist_init>. */
void xlist_destroy(xlist_t* xl);

/* similar to <xlist_init>. */
xlist_t* xlist_new(size_t val_size, xlist_destroy_cb cb);

/* <xl> must be a pointer returned by <xlist_new>. */
void xlist_free(xlist_t* xl);

#if XLIST_ENABLE_CACHE
/* free all cache nodes. */
void xlist_cache_free(xlist_t* xl);
#endif

static inline size_t xlist_size(xlist_t* xl) {
    return xl->size;
}

static inline int xlist_empty(xlist_t* xl) {
    return xl->size == 0;
}

/* return an iterator to the beginning. */
static inline xlist_iter_t xlist_begin(xlist_t* xl) {
    return xl->head.next;
}

/* return an iterator to the end. */
static inline xlist_iter_t xlist_end(xlist_t* xl) {
    return &xl->head;
}

/* return the next iterator of <iter>. */
static inline xlist_iter_t xlist_iter_next(xlist_iter_t iter) {
    return iter->next;
}

/* return a reverse iterator to the beginning. */
static inline xlist_iter_t xlist_rbegin(xlist_t* xl) {
    return xl->head.prev;
}

/* return a reverse iterator to the end.  */
static inline xlist_iter_t xlist_rend(xlist_t* xl) {
    return &xl->head;
}

/* return the next reverse iterator of <iter>. */
static inline xlist_iter_t xlist_riter_next(xlist_iter_t iter) {
    return iter->prev;
}

/* check whether an iterator is valid in a <xlist_t>, equal to "iter != xlist_end(xl)". */
static inline int xlist_iter_valid(xlist_t* xl, xlist_iter_t iter) {
    return iter != &xl->head;
}

/* return a pointer pointed to the element value of <iter>. */
static inline void* xlist_iter_value(xlist_iter_t iter) {
    return (void*) (iter + 1);
}

/* return an iterator of an element value. */
static inline xlist_iter_t xlist_value_iter(void* pvalue) {
    return (xlist_iter_t) pvalue - 1;
}

/* access the first element value (an pointer pointed to the value). */
static inline void* xlist_front(xlist_t* xl) {
    return xlist_iter_value(xlist_begin(xl));
}

/* access the last element value (an pointer pointed to the value). */
static inline void* xlist_back(xlist_t* xl) {
    return xlist_iter_value(xlist_rbegin(xl));
}

/* inserts an element BEFORE <iter>.
 * if <pvalue> is not NULL, copy <val_size> bytes memory of <pvalue> into value,
 * if <pvalue> is NULL, leave value uninitialized. then, set it by yourself.
 * return an iterator pointing to the inserted element.
 */
xlist_iter_t xlist_insert(xlist_t* xl, xlist_iter_t iter, const void* pvalue);

/* removes the element at <iter>, <iter> MUST be valid.
 * return an iterator following the last removed element.
 */
xlist_iter_t xlist_erase(xlist_t* xl, xlist_iter_t iter);

/* clears the elements (no cache). */
void xlist_clear(xlist_t* xl);

/* inserts an element to the beginning. see <xlist_insert>. */
static inline xlist_iter_t xlist_push_front(xlist_t* xl, const void* pvalue) {
    return xlist_insert(xl, xlist_begin(xl), pvalue);
}

/* inserts an element to the end. see <xlist_insert>. */
static inline xlist_iter_t xlist_push_back(xlist_t* xl, const void* pvalue) {
    return xlist_insert(xl, xlist_end(xl), pvalue);
}

/* removes the first element. see <xlist_erase>. */
static inline xlist_iter_t xlist_pop_front(xlist_t* xl) {
    return xlist_erase(xl, xlist_begin(xl));
}

/* removes the last element. see <xlist_erase>. */
static inline xlist_iter_t xlist_pop_back(xlist_t* xl) {
    return xlist_erase(xl, xlist_rbegin(xl));
}

/* allocate memory for an element and insert before <iter>.
 * return a pointer pointed to the element.
 */
static inline void* xlist_alloc(xlist_t* xl, xlist_iter_t iter) {
    return xlist_iter_value(xlist_insert(xl, iter, NULL));
}

/* allocate memory for an element and insert to the beginning.
 * return a pointer pointed to the element.
 */
static inline void* xlist_alloc_front(xlist_t* xl) {
    return xlist_iter_value(xlist_push_front(xl, NULL));
}

/* allocate memory for an element and insert to the end.
 * return a pointer pointed to the element.
 */
static inline void* xlist_alloc_back(xlist_t* xl) {
    return xlist_iter_value(xlist_push_back(xl, NULL));
}

#if XLIST_ENABLE_SORT
/* non-recursive merge sort for xlist. */
void xlist_msort(xlist_t* xl, xlist_compare_cb cmp);
#endif

#if XLIST_ENABLE_CUT

/* cut the element at <iter>, <iter> MUST be valid.
 * return a pointer pointed to the element value.
 * <xlist_cut_free> OR <xlist_paste> MUST be called for the return value.
 */
static inline void* xlist_cut(xlist_t* xl, xlist_iter_t iter) {
    iter->prev->next = iter->next;
    iter->next->prev = iter->prev;
    --xl->size;
    return xlist_iter_value(iter);
}

/* destory an element (no cache) which <xlist_cut> returns (<xlist_destroy_cb> will be called). */
void xlist_cut_free(xlist_t* xl, void* pvalue);

/* paste an element (which <xlist_cut> returns) to <xl> BEFORE <iter>.
 * return a iterator pointed to the <pvalue>.
 * <xl> element type MUST equal to the <pvalue> type.
 */
static inline xlist_iter_t xlist_paste(xlist_t* xl, xlist_iter_t iter, void* pvalue) {
    xlist_iter_t newi = xlist_value_iter(pvalue);

    newi->next = iter;
    newi->prev = iter->prev;
    iter->prev->next = newi;
    iter->prev = newi;
    ++xl->size;
    return newi;
}

/* cut the first element. see <xlist_cut>. */
static inline void* xlist_cut_front(xlist_t* xl) {
    return xlist_cut(xl, xlist_begin(xl));
}

/* cut the last element. see <xlist_cut>. */
static inline void* xlist_cut_back(xlist_t* xl) {
    return xlist_cut(xl, xlist_rbegin(xl));
}

/* paste an element to the beginning. see <xlist_paste>. */
static inline xlist_iter_t xlist_paste_front(xlist_t* xl, void* pvalue) {
    return xlist_paste(xl, xlist_begin(xl), pvalue);
}

/* paste an element to the end. see <xlist_paste>. */
static inline xlist_iter_t xlist_paste_back(xlist_t* xl, void* pvalue) {
    return xlist_paste(xl, xlist_end(xl), pvalue);
}

#endif // XLIST_ENABLE_CUT

#endif // _XLIST_H_
