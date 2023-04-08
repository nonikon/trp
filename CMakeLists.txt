cmake_minimum_required(VERSION 3.4)

project(trp LANGUAGES C)

set(LIBUV_SRC_PATH "./libuv" CACHE PATH
    "libuv source path when LIBUV_EMBEDDED=ON")

option(LIBUV_EMBEDDED "with build-in libuv" ON)
if(LIBUV_EMBEDDED)
    add_subdirectory(${LIBUV_SRC_PATH})
endif()

# get Git current commit id
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    )
endif()

set(generic_sources
    xhash.c
    xlist.c
    xlog.c
    common.c
    crypto.c
    sm4.c
    chacha.c
    ini.c
)
set(generic_defines
    XHASH_ENABLE_CACHE=1
    XLIST_ENABLE_CACHE=1
    XLOG_OUT_CTRL=4
    INI_ALLOW_MULTILINE=0
    INI_MAX_LINE=512
)
if(NOT ${GIT_COMMIT_ID})
    list(APPEND generic_defines GIT_COMMIT_ID="${GIT_COMMIT_ID}")
endif()

# server
set(server_sources
    ${generic_sources}
    http_parser.c
    http_server.c
    server.c
    remote.c
)
set(server_defines
    ${generic_defines}
    HTTP_PARSER_STRICT=0
    WITH_CLIREMOTE
    WITH_CTRLSERVER
)

# client
set(client_sources
    ${generic_sources}
    http_parser.c
    http_server.c
    client.c
    remote.c
)
set(client_defines
    ${generic_defines}
    HTTP_PARSER_STRICT=0
    WITH_CTRLSERVER
)

# tunnel
set(tunnel_sources
    ${generic_sources}
    xclient.c
    tunnel.c
)
set(tunnel_defines
    ${generic_defines}
)

# socks
set(socks_sources
    ${generic_sources}
    xclient.c
    socks.c
)
set(socks_defines
    ${generic_defines}
)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
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

add_executable(trp-client ${client_sources})
target_compile_definitions(trp-client PRIVATE ${client_defines})

add_executable(trp-tunnel ${tunnel_sources})
target_compile_definitions(trp-tunnel PRIVATE ${tunnel_defines})

add_executable(trp-socks ${socks_sources})
target_compile_definitions(trp-socks PRIVATE ${socks_defines})