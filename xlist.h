/*
 * Copyright (C) 2019-2021 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XLIST_H_
#define _XLIST_H_

#include <stddef.h>

/* doubly-linked list, similar to C++ STL std::list */

#ifdef HAVE_XCONFIG_H
#include "xconfig.h"
#else

/* cache can decrease memory allocation. node will be put into cache
 * when it being erased, and next insertion will pop one node from
 * cache. define 'XLIST_ENABLE_CACHE=1' to enable it. */
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

#endif

typedef struct xlist        xlist_t;
typedef struct xlist_node   xlist_node_t;
typedef struct xlist_node*  xlist_iter_t;

typedef void (*xlist_destroy_cb)(void* pvalue);
typedef int  (*xlist_compare_cb)(void* l, void* r);

struct xlist_node
{
    struct xlist_node*  prev;
    struct xlist_node*  next;
    // value
};

struct xlist
{
    size_t              size;
    size_t              val_size;   // element value size in 'xlist_node_t'
    xlist_destroy_cb    destroy_cb; // called when element destroy
#if XLIST_ENABLE_CACHE
    xlist_node_t*       cache;      // cache nodes
#endif
    xlist_node_t        head;
};

/* initialize a 'xlist_t', 'val_size' is the size of element value.
 * 'cb' is called when element destroy, can be NULL, but it usually
 * can't be NULL when value type is a pointer or contains a pointer. */
xlist_t* xlist_init(xlist_t* xl, size_t val_size, xlist_destroy_cb cb);
/* destroy a 'xlist_t' which has called 'xlist_init'. */
void xlist_destroy(xlist_t* xl);

/* allocate memory for a 'xlist_t' and initialize it. */
xlist_t* xlist_new(size_t val_size, xlist_destroy_cb cb);
/* release memory for a 'xlist_t' which 'xlist_new' returns. */
void xlist_free(xlist_t* xl);

#if XLIST_ENABLE_CACHE
/* free all cache nodes in a 'xlist_t'. */
void xlist_cache_free(xlist_t* xl);
#endif

/* return the number of elements. */
#define xlist_size(xl)  ((xl)->size)
/* checks whether the container is empty. */
#define xlist_empty(xl) ((xl)->size == 0)

/* return an iterator to the beginning. */
#define xlist_begin(xl)         ((xl)->head.next)
/* return an iterator to the end. */
#define xlist_end(xl)           (&(xl)->head)
/* return the next iterator of 'iter'. */
#define xlist_iter_next(iter)   ((iter)->next)
/* return a reverse iterator to the beginning. */
#define xlist_rbegin(xl)        ((xl)->head.prev)
/* return a reverse iterator to the end.  */
#define xlist_rend(xl)          (&(xl)->head)
/* return the next reverse iterator of 'iter'. */
#define xlist_riter_next(iter)  ((iter)->prev)

/* check whether an iterator is valid in a 'xlist_t', equal to "iter != xlist_end(xl)". */
#define xlist_iter_valid(xl, iter)  ((iter) != &(xl)->head)
/* return a pointer pointed to the element value of 'iter'. */
#define xlist_iter_value(iter)      ((void*)((iter) + 1))
/* return an iterator of an element value. */
#define xlist_value_iter(pvalue)    ((xlist_iter_t)(pvalue) - 1)

/* access the first element value (an pointer pointed to the value). */
#define xlist_front(xl) xlist_iter_value(xlist_begin(xl))
/* access the last element value (an pointer pointed to the value). */
#define xlist_back(xl)  xlist_iter_value(xlist_rbegin(xl))

/* inserts an element BEFORE 'iter'.
 * if 'pvalue' is not NULL, copy 'val_size' bytes memory of 'pvalue' into value,
 * if 'pvalue' is NULL, leave value uninitialized. then, set it by yourself.
 * return an iterator pointing to the inserted element. */
xlist_iter_t xlist_insert(xlist_t* xl, xlist_iter_t iter, const void* pvalue);
/* removes the element at 'iter', 'iter' MUST be valid.
 * return an iterator following the last removed element. */
xlist_iter_t xlist_erase(xlist_t* xl, xlist_iter_t iter);
/* clears the elements (no cache) in a 'xlist_t'. */
void xlist_clear(xlist_t* xl);

#if XLIST_ENABLE_SORT
/* non-recursive merge sort for xlist. */
void xlist_msort(xlist_t* xl, xlist_compare_cb cmp);
#endif

#if XLIST_ENABLE_CUT
/* cut the element at 'iter', 'iter' MUST be valid.
 * return a pointer pointed to the element value.
 * 'xlist_cut_free()' OR 'xlist_paste()' MUST be called for the return value. */
void* xlist_cut(xlist_t* xl, xlist_iter_t iter);
/* destory an element which 'xlist_cut' returns ('xlist_destroy_cb' will be called). */
void xlist_cut_free(xlist_t* xl, void* pvalue);
/* paste an element (which 'xlist_cut' returns) to 'xl' BEFORE 'iter'.
 * return a iterator pointed to the 'pvalue'.
 * 'xl' element type MUST equal to the 'pvalue' type. */
xlist_iter_t xlist_paste(xlist_t* xl, xlist_iter_t iter, void* pvalue);
#endif // XLIST_ENABLE_CUT

/* inserts an element to the beginning. see 'xlist_insert'. */
#define xlist_push_front(xl, pvalue)    xlist_insert(xl, xlist_begin(xl), pvalue)
/* inserts an element to the end. see 'xlist_insert'. */
#define xlist_push_back(xl, pvalue)     xlist_insert(xl, xlist_end(xl), pvalue)
/* removes the first element. see 'xlist_erase'. */
#define xlist_pop_front(xl)             xlist_erase(xl, xlist_begin(xl))
/* removes the last element. see 'xlist_erase'. */
#define xlist_pop_back(xl)              xlist_erase(xl, xlist_rbegin(xl))

/* allocate memory for an element and insert before 'iter'.
 * return a pointer pointed to the element.  */
#define xlist_alloc(xl, iter)           xlist_iter_value(xlist_insert(xl, iter, NULL))
/* allocate memory for an element and insert to the beginning.
 * return a pointer pointed to the element.  */
#define xlist_alloc_front(xl)           xlist_iter_value(xlist_push_front(xl, NULL))
/* allocate memory for an element and insert to the end.
 * return a pointer pointed to the element.  */
#define xlist_alloc_back(xl)            xlist_iter_value(xlist_push_back(xl, NULL))

#if XLIST_ENABLE_CUT
/* cut the first element. see 'xlist_cut'. */
#define xlist_cut_front(xl)             xlist_cut(xl, xlist_begin(xl))
/* cut the last element. see 'xlist_cut'. */
#define xlist_cut_back(xl)              xlist_cut(xl, xlist_rbegin(xl))
/* paste an element to the beginning. see 'xlist_paste'. */
#define xlist_paste_front(xl, pvalue)   xlist_paste(xl, xlist_begin(xl), pvalue)
/* paste an element to the end. see 'xlist_paste'. */
#define xlist_paste_back(xl, pvalue)    xlist_paste(xl, xlist_end(xl), pvalue)
#endif // XLIST_ENABLE_CUT

#endif // _XLIST_H_
