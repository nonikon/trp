/*
 * Copyright (C) 2019-2023 nonikon@qq.com.
 * All rights reserved.
 */

#include "xlog.h"

#if XLOG_OUT_CTRL > XLOG_NONE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

unsigned xlog_out_level = XLOG_DEBUG;

static unsigned rotate_ctrl = 8;
static unsigned out_bytes = 0;
static unsigned out_max_bytes = 10 * 1024 * 1024;
static unsigned out_name_idx = 0;
static char*    out_file_path = NULL;
static char     out_buf[XLOG_LINE_MAX];

#ifdef _WIN32
#include <windows.h>

static HANDLE out_fd = INVALID_HANDLE_VALUE;

#if XLOG_MULTITHREAD
static PCRITICAL_SECTION lock;
#endif

static void init_out_name_idx()
{
    char* path = _strdup(out_file_path);
    char* name;
    int len, i;
    WIN32_FIND_DATAA fdata;
    HANDLE fh;

    for (i = (int) strlen(path); --i >= 0; ) {
        if (path[i] == '/' || path[i] == '\\')
            break;
    }

    /* [D:\test\dir\abc.log] -> [D:\test\dir\*], [abc.log]
       [abc.log] -> [*], [abc.log] */
    name = out_file_path + i + 1;

    path[i + 1] = '*';
    path[i + 2] = '\0';

    out_name_idx = 0;

    len = (int) strlen(name);
    fh = FindFirstFileA(path, &fdata);

    if (fh != INVALID_HANDLE_VALUE) {
        /* traverse directory */
        do {
            if (!strncmp(fdata.cFileName, name, len)
                && fdata.cFileName[len]) {
                /* string 'cFileName' start with string 'name'
                   ex: 'cFileName' -> "log.txt.1"
                       'name'      -> "log.txt" */
                i = atoi(fdata.cFileName + len + 1);
                if (out_name_idx < (unsigned) i)
                    out_name_idx = (unsigned) i;
            }
        } while (FindNextFileA(fh, &fdata));

        FindClose(fh);
    }

    free(path);
}

static void logfile_rotate()
{
    unsigned sz = (unsigned) strlen(out_file_path) + 12;
    char* temp = malloc(sz);

    snprintf(temp, sz, "%s.%d", out_file_path, ++out_name_idx);
    /* ignore failures */
    CloseHandle(out_fd);
    MoveFileExA(out_file_path, temp, MOVEFILE_REPLACE_EXISTING);

    out_fd = CreateFileA(out_file_path,
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    NULL,
                    CREATE_ALWAYS,  /* overwrite exists */
                    FILE_ATTRIBUTE_NORMAL /* | FILE_FLAG_NO_BUFFERING */,
                    NULL);

    if (out_name_idx > rotate_ctrl) {
        /* remove the file which out of date */
        snprintf(temp, sz, "%s.%d", out_file_path, out_name_idx - rotate_ctrl);
        DeleteFileA(temp);
    }

    free(temp);
}

int xlog_init(const char* file_path)
{
    int opensucc = 1;

    xlog_exit();

#if XLOG_MULTITHREAD
    if (!lock) {
        lock = malloc(sizeof(CRITICAL_SECTION));
        InitializeCriticalSection(lock);
    }
#endif
    if (!file_path) {
        out_fd = GetStdHandle(STD_OUTPUT_HANDLE);
    } else {
        out_fd = CreateFileA(file_path,
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_ALWAYS, /* create if not exists */
                    FILE_ATTRIBUTE_NORMAL /* | FILE_FLAG_NO_BUFFERING */,
                    NULL);
        /* open output file failed, switch to STDOUT */
        if (out_fd == INVALID_HANDLE_VALUE) {
            out_fd = GetStdHandle(STD_OUTPUT_HANDLE);
            opensucc = 0;
        }
    }

    if (out_fd != INVALID_HANDLE_VALUE) {
        if (GetFileType(out_fd) == FILE_TYPE_DISK) {
            /* seek to end (append) */
            SetFilePointer(out_fd, 0, 0, FILE_END);

            out_file_path = _strdup(file_path);
            out_bytes = (unsigned) GetFileSize(out_fd, NULL);

            if (out_bytes == INVALID_FILE_SIZE)
                out_bytes = 0;
            init_out_name_idx();
        }

        /* FILE_TYPE_CHAR when file_path is "nul"... */
        return opensucc ? 0 : -1;
    }

    return -1;
}

void xlog_ctrl(unsigned level, unsigned max_size, unsigned rotate)
{
    xlog_out_level = level;

    if (max_size > 0)
        out_max_bytes = max_size;
    if (rotate > 0)
        rotate_ctrl = rotate;
}

void xlog_exit()
{
    if (out_fd != INVALID_HANDLE_VALUE) {
        CloseHandle(out_fd);
        out_fd = INVALID_HANDLE_VALUE;
    }
    if (out_file_path) {
        free(out_file_path);
        out_file_path = NULL;
    }
}

void xlog_println(const char* tag, const char* fmt, ...)
{
    DWORD nw = 0;
    SYSTEMTIME t;
    int off;
    va_list ap;

#if XLOG_MULTITHREAD
    EnterCriticalSection(lock);
#endif

    GetLocalTime(&t);
#if XLOG_WITH_TID
    off = snprintf(out_buf, XLOG_LINE_MAX, "%02d/%02d %02d:%02d:%02d %s %u ",
        t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, tag, (unsigned) GetCurrentThreadId());
#else
    off = snprintf(out_buf, XLOG_LINE_MAX, "%02d/%02d %02d:%02d:%02d %s ",
        t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, tag);
#endif
    va_start(ap, fmt);
    off += vsnprintf(out_buf + off, XLOG_LINE_MAX - 2 - off, fmt, ap);
    va_end(ap);

    out_buf[off++] = '\r';
    out_buf[off++] = '\n';

    if (WriteFile(out_fd, out_buf, off, &nw, NULL) && out_file_path) {
        /* output is a file, do rotate check */
#if XLOG_SYNC_WRITE
        FlushFileBuffers(out_fd);
#endif
        out_bytes += nw;
        if (out_bytes > out_max_bytes) {
            logfile_rotate();
            out_bytes = 0;
        }
    }

#if XLOG_MULTITHREAD
    LeaveCriticalSection(lock);
#endif
}

void xlog_printhex(const unsigned char* data, unsigned int len)
{
    static const char i2c[16] = "0123456789ABCDEF";

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int bytes = 0;
    DWORD nw;

#if XLOG_MULTITHREAD
    EnterCriticalSection(lock);
#endif

    while (i < len) {
        out_buf[j++] = ' ';
        out_buf[j++] = i2c[data[i] >> 4];
        out_buf[j++] = i2c[data[i++] & 0x0F];

        if (j == 3 * XLOG_HEX_MAX) {
            out_buf[j++] = '\r';
            out_buf[j++] = '\n';

            if (WriteFile(out_fd, out_buf, j, &nw, NULL))
                bytes += nw;

            j = 0;
        }
    }

    if (j) {
        out_buf[j++] = '\r';
        out_buf[j++] = '\n';

        if (WriteFile(out_fd, out_buf, j, &nw, NULL))
            bytes += nw;
    }

    if (out_file_path) {
#if XLOG_SYNC_WRITE
        FlushFileBuffers(out_fd);
#endif
        out_bytes += bytes;
        if (out_bytes > out_max_bytes) {
            logfile_rotate();
            out_bytes = 0;
        }
    }

#if XLOG_MULTITHREAD
    LeaveCriticalSection(lock);
#endif
}

#else // !_WIN32

#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#if XLOG_MULTITHREAD
#include <pthread.h>        /* for pthread_mutex */
#endif
#if XLOG_WITH_TID
#include <sys/syscall.h>    /* for SYS_gettid */
#endif

static int out_fd = STDOUT_FILENO;

#if XLOG_MULTITHREAD
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static void init_out_name_idx()
{
    char* path = strdup(out_file_path);
    char* name;
    int len, i;
    struct dirent* ent;
    DIR* dir;

    for (i = strlen(path); --i >= 0; ) {
        if (path[i] == '/')
            break;
    }

    /* [/usr/src/abc.log] -> [/usr/src], [abc.log]
       [abc.log] -> [.], [abc.log] */
    name = out_file_path + i + 1;

    path[i + 1] = '.';
    path[i + 2] = '\0';

    out_name_idx = 0;

    len = strlen(name);
    dir = opendir(path);

    if (dir) {
        /* traverse directory */
        while ((ent = readdir(dir)) != NULL) {
            /* no need check '.' and '..'  */
            if (!strncmp(ent->d_name, name, len)
                && ent->d_name[len]) {
                /* string 'd_name' start with string 'name'
                   ex: 'd_name' -> "log.txt.1"
                       'name'   -> "log.txt" */
                i = atoi(ent->d_name + len + 1);
                if (out_name_idx < i)
                    out_name_idx = i;
            }
        }
        closedir(dir);
    }

    free(path);
}

static void logfile_rotate()
{
    char* temp = malloc(strlen(out_file_path) + 12);

    sprintf(temp, "%s.%d", out_file_path, ++out_name_idx);
    /* ignore failures */
    close(out_fd);
    rename(out_file_path, temp);

#ifdef O_CLOEXEC
    out_fd = open(out_file_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
#else
    out_fd = open(out_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    fcntl(out_fd, F_SETFD, fcntl(out_fd, F_GETFD) | FD_CLOEXEC);
#endif

    if (out_name_idx > rotate_ctrl) {
        /* remove the file which out of date */
        sprintf(temp, "%s.%d", out_file_path, out_name_idx - rotate_ctrl);
        unlink(temp);
    }

    free(temp);
}

int xlog_init(const char* file_path)
{
    struct stat fst;

    xlog_exit();

    if (!file_path) return 0;

#ifdef O_CLOEXEC
    out_fd = open(file_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
#else
    out_fd = open(file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
#endif

    if (out_fd < 0) {
        out_fd = STDOUT_FILENO;
        return -1;
    }
#ifndef O_CLOEXEC
    fcntl(out_fd, F_SETFD, fcntl(out_fd, F_GETFD) | FD_CLOEXEC);
#endif

    if (fstat(out_fd, &fst) == 0 && S_ISREG(fst.st_mode)) {
        out_bytes = (unsigned) fst.st_size;
        out_file_path = strdup(file_path);

        init_out_name_idx();
    }

    /* S_ISCHR when file_path is "/dev/null"... */
    return 0;
}

void xlog_ctrl(unsigned level, unsigned max_size, unsigned rotate)
{
    xlog_out_level = level;

    if (max_size > 0)
        out_max_bytes = max_size;
    if (rotate > 0)
        rotate_ctrl = rotate;
}

void xlog_exit()
{
    if (out_fd > STDERR_FILENO) {
        close(out_fd);
        out_fd = STDOUT_FILENO;
    }
    if (out_file_path) {
        free(out_file_path);
        out_file_path = NULL;
    }
}

void xlog_println(const char* tag, const char* fmt, ...)
{
    struct tm t;
    time_t s;
    int off;
    int nw;
    va_list ap;

#if XLOG_MULTITHREAD
    pthread_mutex_lock(&lock);
#endif

    time(&s);
    localtime_r(&s, &t);
#if XLOG_WITH_TID
    off = sprintf(out_buf, "%02d/%02d %02d:%02d:%02d %s %u ",
        t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, tag, (unsigned) syscall(SYS_gettid));
#else
    off = sprintf(out_buf, "%02d/%02d %02d:%02d:%02d %s ",
        t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, tag);
#endif
    va_start(ap, fmt);
    off += vsnprintf(out_buf + off, XLOG_LINE_MAX - 1 - off, fmt, ap);
    va_end(ap);

    out_buf[off++] = '\n';

    nw = (int) write(out_fd, out_buf, off);

    if (nw > 0 && out_file_path) {
#if XLOG_SYNC_WRITE
        fdatasync(out_fd);
#endif
        out_bytes += nw;
        if (out_bytes > out_max_bytes) {
            logfile_rotate();
            out_bytes = 0;
        }
    }

#if XLOG_MULTITHREAD
    pthread_mutex_unlock(&lock);
#endif
}

void xlog_printhex(const unsigned char* data, unsigned int len)
{
    static const char i2c[16] = "0123456789ABCDEF";

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int bytes = 0;

    int nw;

#if XLOG_MULTITHREAD
    pthread_mutex_lock(&lock);
#endif

    while (i < len) {
        out_buf[j++] = ' ';
        out_buf[j++] = i2c[data[i] >> 4];
        out_buf[j++] = i2c[data[i++] & 0x0F];

        if (j == 3 * XLOG_HEX_MAX) {
            out_buf[j++] = '\n';

            nw = (int) write(out_fd, out_buf, j);
            if (nw > 0)
                bytes += nw;

            j = 0;
        }
    }

    if (j) {
        out_buf[j++] = '\n';

        nw = (int) write(out_fd, out_buf, j);
        if (nw > 0)
            bytes += nw;
    }

    if (out_file_path) {
#if XLOG_SYNC_WRITE
        fdatasync(out_fd);
#endif
        out_bytes += bytes;
        if (out_bytes > out_max_bytes) {
            logfile_rotate();
            out_bytes = 0;
        }
    }

#if XLOG_MULTITHREAD
    pthread_mutex_unlock(&lock);
#endif
}

#endif // _WIN32

#endif // XLOG_OUT_CTRL > 0
