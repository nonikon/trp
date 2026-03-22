cmake_minimum_required(VERSION 3.10)

project(trp LANGUAGES C)

set(LIBUV_SRC_PATH "./libuv" CACHE PATH "Enable build-in libuv and set source path")

option(DISABLE_LOG "Disable log output" OFF)
option(DISABLE_CTRLSERVER "Disable http control server" OFF)
option(DISABLE_PTYLOGIN "Launch remote terminal without login (Unix remote only)" OFF)

# Get Git current commit id
find_package(Git QUIET)
if(GIT_FOUND)
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_ID OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
  )
endif()

# generic
if(LIBUV_SRC_PATH)
  add_subdirectory(${LIBUV_SRC_PATH} EXCLUDE_FROM_ALL)
  include_directories(${LIBUV_SRC_PATH}/include)
  set(generic_libraries uv_a)
else()
  set(generic_libraries uv)
endif()
set(generic_sources xhash.c xlist.c xlog.c common.c crypto.c sm4.c chacha.c ini.c)
set(generic_defines
  XLOG_MULTITHREAD=0 XLOG_WITH_TID=0 XHASH_ENABLE_CACHE=1
  XLIST_ENABLE_CACHE=1 INI_ALLOW_MULTILINE=0 INI_MAX_LINE=512
)
if(DISABLE_LOG)
  list(APPEND generic_defines XLOG_OUT_CTRL=0)
endif()
if(NOT ${GIT_COMMIT_ID})
  list(APPEND generic_defines GIT_COMMIT_ID="${GIT_COMMIT_ID}")
endif()
if(MSVC)
  list(APPEND generic_defines _CRT_SECURE_NO_WARNINGS)
endif()
if(NOT MSVC)
  add_compile_options(-Wall)
endif()

# server
set(server_sources ${generic_sources} server.c remote.c)
set(server_defines ${generic_defines} WITH_CLIREMOTE)
set(server_libraries ${generic_libraries})
if(NOT DISABLE_CTRLSERVER)
  list(APPEND server_sources http_parser.c http_server.c)
  list(APPEND server_defines WITH_CTRLSERVER HTTP_PARSER_STRICT=0)
endif()
if(NOT DISABLE_PTYLOGIN)
  list(APPEND server_defines WITH_PTYLOGIN)
endif()
if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|Linux|NetBSD|OpenBSD")
  list(APPEND server_libraries PRIVATE util)
endif()
add_executable(trp-server ${server_sources})
target_compile_definitions(trp-server PRIVATE ${server_defines})
target_link_libraries(trp-server PRIVATE ${server_libraries})

# client
set(client_sources ${generic_sources} client.c remote.c)
set(client_defines ${generic_defines})
set(client_libraries ${generic_libraries})
if(NOT DISABLE_CTRLSERVER)
  list(APPEND client_sources http_parser.c http_server.c)
  list(APPEND client_defines WITH_CTRLSERVER HTTP_PARSER_STRICT=0)
endif()
if(NOT DISABLE_PTYLOGIN)
  list(APPEND client_defines WITH_PTYLOGIN)
endif()
if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|Linux|NetBSD|OpenBSD")
  list(APPEND client_libraries PRIVATE util)
endif()
add_executable(trp-client ${client_sources})
target_compile_definitions(trp-client PRIVATE ${client_defines})
target_link_libraries(trp-client PRIVATE ${client_libraries})

# tunnel
set(tunnel_sources ${generic_sources} xclient.c tunnel.c)
set(tunnel_defines ${generic_defines})
set(tunnel_libraries ${generic_libraries})
add_executable(trp-tunnel ${tunnel_sources})
target_compile_definitions(trp-tunnel PRIVATE ${tunnel_defines})
target_link_libraries(trp-tunnel PRIVATE ${tunnel_libraries})

# socks
set(socks_sources ${generic_sources} xclient.c socks.c)
set(socks_defines ${generic_defines})
set(socks_libraries ${generic_libraries})
add_executable(trp-socks ${socks_sources})
target_compile_definitions(trp-socks PRIVATE ${socks_defines})
target_link_libraries(trp-socks PRIVATE ${socks_libraries})

# shell
set(shell_sources xlist.c common.c crypto.c sm4.c chacha.c ini.c shell.c)
set(shell_defines ${generic_defines})
set(shell_libraries ${generic_libraries})
add_executable(trp-shell ${shell_sources})
target_compile_definitions(trp-shell PRIVATE ${shell_defines})
target_link_libraries(trp-shell PRIVATE ${shell_libraries})

install(TARGETS trp-server trp-client trp-tunnel trp-socks trp-shell)