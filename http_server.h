/*
 * Copyright (C) 2021 nonikon@qq.com.
 * All rights reserved.
 */

#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_

#include <uv.h>

int http_server_start(uv_loop_t* loop, const char* ip, int port);
int http_server_stop();

#endif // _HTTP_SERVER_H_