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

set(generic_sources
    xlist.c
    xlog.c
    common.c
    crypto.c
    sm4.c
    chacha.c
)

# server
set(server_sources
    ${generic_sources}
    xhash.c
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

# client
set(client_sources
    ${generic_sources}
    client.c
)
set(client_defines
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
)

# tunnel
set(tunnel_sources
    ${generic_sources}
    xclient.c
    tunnel.c
)
set(tunnel_defines
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
)

# socks
set(socks_sources
    ${generic_sources}
    xclient.c
    socks.c
)
set(socks_defines
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
)

if(MSVC)
    add_compile_definitions(
        _WINSOCK_DEPRECATED_NO_WARNINGS
        _CRT_SECURE_NO_WARNINGS
    )
else()
    add_compile_options(-Wall)
endif()

if(LIBUV_EMBEDDED)
    include_directories(${LIBUV_SRC_PATH}/include)
    link_libraries(uv_a)
else()
    link_libraries(uv)
endif()

add_executable(trp-server ${server_sources})
target_compile_definitions(trp-server PRIVATE ${server_defines})
# target_compile_options(trp-server PRIVATE ${server_cflags})

add_executable(trp-client ${client_sources})
target_compile_definitions(trp-client PRIVATE ${client_defines})
# target_compile_options(trp-client PRIVATE ${client_cflags})

add_executable(trp-tunnel ${tunnel_sources})
target_compile_definitions(trp-tunnel PRIVATE ${tunnel_defines})
# target_compile_options(trp-tunnel PRIVATE ${tunnel_cflags})

add_executable(trp-socks ${socks_sources})
target_compile_definitions(trp-socks PRIVATE ${socks_defines})
# target_compile_options(trp-socks PRIVATE ${socks_cflags})