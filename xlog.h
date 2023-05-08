/*
 * Copyright (C) 2019-2023 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _XLOG_H_
#define _XLOG_H_

#define XLOG_NONE           (0)
#define XLOG_ERROR          (XLOG_NONE + 1)
#define XLOG_WARN           (XLOG_NONE + 2)
#define XLOG_INFO           (XLOG_NONE + 3)
#define XLOG_DEBUG          (XLOG_NONE + 4)

#ifndef XLOG_OUT_CTRL
#define XLOG_OUT_CTRL       XLOG_DEBUG
#endif

#ifndef XLOG_MULTITHREAD
#define XLOG_MULTITHREAD    1   /* multi-thread support */
#endif

#ifndef XLOG_WITH_TID
#define XLOG_WITH_TID       1   /* output thread identification */
#endif

#ifndef XLOG_WITH_EXTRA
#define XLOG_WITH_EXTRA     1   /* output __FILE__, __LINE__, __FUNCTION__... */
#endif

#ifndef XLOG_SYNC_WRITE
#define XLOG_SYNC_WRITE     0   /* flush file buffer after write */
#endif

#ifndef XLOG_HEX_MAX
#define XLOG_HEX_MAX        16
#endif

#ifndef XLOG_LINE_MAX
#define XLOG_LINE_MAX       1024
#endif

#if XLOG_OUT_CTRL > XLOG_NONE
extern unsigned xlog_out_level;
#endif

#if XLOG_WITH_EXTRA
#define XLOG_FORMAT(fmt)    "%s:%d - " fmt, __FUNCTION__, __LINE__
#else
#define XLOG_FORMAT(fmt)    "- " fmt
#endif

#if XLOG_OUT_CTRL >= XLOG_ERROR
#define xlog_error(fmt, ...) \
    do { \
        if (xlog_out_level >= XLOG_ERROR) \
            xlog_println("E", XLOG_FORMAT(fmt), ##__VA_ARGS__); \
    } while (0)
#else
#define xlog_error(fmt, ...)
#endif
#if XLOG_OUT_CTRL >= XLOG_WARN
#define xlog_warn(fmt, ...) \
    do { \
        if (xlog_out_level >= XLOG_WARN) \
            xlog_println("W", XLOG_FORMAT(fmt), ##__VA_ARGS__); \
    } while (0)
#else
#define  xlog_warn(fmt, ...)
#endif
#if XLOG_OUT_CTRL >= XLOG_INFO
#define xlog_info(fmt, ...) \
    do { \
        if (xlog_out_level >= XLOG_INFO) \
            xlog_println("I", XLOG_FORMAT(fmt), ##__VA_ARGS__); \
    } while (0)
#else
#define  xlog_info(fmt, ...)
#endif
#if XLOG_OUT_CTRL >= XLOG_DEBUG
#define xlog_debug(fmt, ...) \
    do { \
        if (xlog_out_level >= XLOG_DEBUG) \
            xlog_println("D", XLOG_FORMAT(fmt), ##__VA_ARGS__); \
    } while (0)
#define xlog_hex(data, len) \
    do { \
        if (xlog_out_level >= XLOG_DEBUG) \
            xlog_printhex(data, len); \
    } while (0)
#else
#define xlog_debug(fmt, ...)
#define xlog_hex(data, len)
#endif

#if XLOG_OUT_CTRL > XLOG_NONE
/* open log file. 'file_path' can be 'NULL' (default to 'stdout').*/
int xlog_init(const char* file_path);
/* set log level (default XLOG_DEBUG),
 * and log file max size (bytes, default 5M),
 * and log file max count (default 3). */
void xlog_ctrl(unsigned level, unsigned max_size, unsigned rotate);
/* close the log file */
void xlog_exit();
/* ... */
void xlog_println(const char* tag, const char* fmt, ...);
void xlog_printhex(const unsigned char* data, unsigned int len);
#else
#define xlog_init(...)
#define xlog_ctrl(...)
#define xlog_exit(...)
#define xlog_println(...)
#define xlog_printhex(...)
#endif

#endif  // _XLOG_H_