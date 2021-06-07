cmake_minimum_required(VERSION 3.4)

project(trp LANGUAGES C)

set(LIBUV_SRC_PATH "./libuv" CACHE PATH
    "libuv source path when LIBUV_EMBEDDED=ON")

option(LIBUV_EMBEDDED "with build-in libuv" ON)
if(LIBUV_EMBEDDED)
    add_subdirectory(${LIBUV_SRC_PATH})
endif()

# if(WIN32)
#     set(libs ws2_32 psapi user32 userenv iphlpapi)
# else()
#     set(libs pthread dl)
# endif()

set(server_sources
    xhash.c
    xlist.c
    xlog.c
    common.c
    http_parser.c
    http_server.c
    server.c
)
set(server_defines
    HTTP_PARSER_STRICT=0
    XHASH_ENABLE_CACHE=1
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
)

set(client_sources
    xlist.c
    xlog.c
    common.c
    client.c
)
set(client_defines
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
)

set(tunnel_sources
    xlist.c
    xlog.c
    common.c
    tunnel.c
)
set(tunnel_defines
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
)

add_executable(trp-server ${server_sources})
if(LIBUV_EMBEDDED)
    target_include_directories(trp-server PRIVATE ${LIBUV_SRC_PATH}/include)
    target_link_libraries(trp-server uv_a)
else()
    target_link_libraries(trp-server uv)
endif()
target_compile_definitions(trp-server PRIVATE ${server_defines})
# target_compile_options(trp-server PRIVATE ${server_cflags})

add_executable(trp-client ${client_sources})
if(LIBUV_EMBEDDED)
    target_include_directories(trp-client PRIVATE ${LIBUV_SRC_PATH}/include)
    target_link_libraries(trp-client uv_a)
else()
    target_link_libraries(trp-client uv)
endif()
target_compile_definitions(trp-client PRIVATE ${client_defines})
# target_compile_options(trp-client PRIVATE ${client_cflags})

add_executable(trp-tunnel ${tunnel_sources})
if(LIBUV_EMBEDDED)
    target_include_directories(trp-tunnel PRIVATE ${LIBUV_SRC_PATH}/include)
    target_link_libraries(trp-tunnel uv_a)
else()
    target_link_libraries(trp-tunnel uv)
endif()
target_compile_definitions(trp-tunnel PRIVATE ${tunnel_defines})
# target_compile_options(trp-tunnel PRIVATE ${tunnel_cflags})