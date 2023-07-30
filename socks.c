/*
 * Copyright (C) 2021-2023 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>
#ifndef _WIN32
#include <unistd.h> /* for daemon() */
#include <signal.h> /* for signal() */
#include <sys/resource.h> /* for setrlimit() */
#endif

#include "xclient.h"

/*  --------------         --------------         --------------
 * | proxy-server | <---> | proxy-client | <---> | applications |
 *  --------------         --------------         --------------
 *                         (socks-server)         (socks-client)
 *
 * SOCKS5 Protocol: https://www.ietf.org/rfc/rfc1928.txt
 */

static uv_udp_t io_usserver; /* udp socks server listen io */

/* SOCKS4/SOCKS5 handshake */
static int socks_handshake(xclient_ctx_t* ctx, uv_buf_t* buf)
{
    if (ctx->stage == STAGE_INIT) {

        /* 'VER' == 0x05 (SOCKS5) */
        if (buf->base[0] == 0x05) {
            /* SOCKS5 client request:
             * +-----+----------+----------+
             * | VER | NMETHODS | METHODS  |
             * +-----+----------+----------+
             * |  1  |    1     | 1 to 255 |
             * +-----+----------+----------+
             * SOCKS5 server response:
             * +-----+--------+
             * | VER | METHOD |
             * +-----+--------+
             * |  1  |   1    |
             * +-----+--------+
             * METHOD:
             *   X'00' NO AUTHENTICATION REQUIRED
             *   X'01' GSSAPI
             *   X'02' USERNAME/PASSWORD
             *   X'03' to X'7F' IANA ASSIGNED
             *   X'80' to X'FE' RESERVED FOR PRIVATE METHODS
             *   X'FF' NO ACCEPTABLE METHODS
             */

            if (buf->len < 3 || buf->base[1] == 0) { /* 'NMETHODS' == 0 */
                XLOGW("invalid socks5 select message from client.");
                return -1;
            }

            XLOGD("socks5 select message from client: %d bytes, %d methods.",
                buf->len, buf->base[1]);

            buf->base[1] = 0x00; /* select 'METHOD' 0x00 */
            buf->len = 2;

            ctx->stage = STAGE_COMMAND;
            return 0;
        }

        /* 'VER' == 0x04 (SOCKS4) */
        if (buf->base[0] == 0x04) {
            /* SOCKS4 client request:
             * +----+----+---------+-------+----------+------+
             * | VN | CD | DSTPORT | DSTIP |  USERID  | NULL |
             * +----+----+---------+-------+----------+------+
             * | 1  | 1  |    2    |   4   | Variable |   1  |
             * +----+----+---------+-------+----------+------+
             *  SOCKS4 server response:
             * +----+----+---------+-------+
             * | VN | CD | DSTPORT | DSTIP |
             * +----+----+---------+-------+
             * | 1  | 1  |    2    |   4   |
             * +----+----+---------+-------+
             */

            if (buf->len < 9 || buf->base[1] != 0x01) {/* 'CD' != 0x01 (CONNECT) */
                XLOGW("invalid socks4 command from client.");
                return -1;
            }

            init_connect_command(ctx, CMD_CONNECT_IPV4,
                *(u16_t*) (buf->base + 2), (u8_t*) (buf->base + 4), 4);

            buf->base[0] = 0x00; /* set 'VN' to 0x00 */
            buf->len = 8;

            if (connect_xserver(ctx) == 0) {
                /* assume that proxy server was connected successfully. */

                /* stop reading from socks client until proxy server connected. */
                uv_read_stop((uv_stream_t*) &ctx->xclient.t.io);

                buf->base[1] = 90; /* set 'CD' to 90 */
                return 0;
            }

            /* connect proxy server failed immediately. */
            buf->base[1] = 91; /* set 'CD' to 91 */
            return 1;
        }

        XLOGW("invalid socks protocol version (%d).", buf->base[0]);
        return -1;
    }

    if (ctx->stage == STAGE_COMMAND) {
        /* SOCKS5 client request:
         * +-----+-----+-------+------+----------+----------+
         * | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
         * +-----+-----+-------+------+----------+----------+
         * |  1  |  1  | X'00' |  1   | Variable |    2     |
         * +-----+-----+-------+------+----------+----------+
         * SOCKS5 server response:
         * +-----+-----+-------+------+----------+----------+
         * | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
         * +-----+-----+-------+------+----------+----------+
         * |  1  |  1  | X'00' |  1   | Variable |    2     |
         * +-----+-----+-------+------+----------+----------+
         * CMD:
         *   X'01' CONNECT
         *   X'02' BIND
         *   X'03' UDP ASSOCIATE
         * ATYP:
         *   X'01' IP V4 address
         *   X'03' DOMAINNAME
         *   X'04' IP V6 address
         * REP:
         *   X'00' succeeded
         *   X'01' general SOCKS server failure
         *   X'02' connection not allowed by ruleset
         *   X'03' Network unreachable
         *   X'04' Host unreachable
         *   X'05' Connection refused
         *   X'06' TTL expired
         *   X'07' Command not supported
         *   X'08' Address type not supported
         *   X'09' to X'FF' unassigned
         */

        if (buf->len < 7
                || buf->base[0] != 0x05    /* 'VER' != 0x05 */
                || buf->base[2] != 0x00) { /* 'RSV' != 0x00 */
            XLOGW("invalid socks5 request from client.");
            return -1;
        }

        if (buf->base[1] == 0x01) { /* 'CMD' == 0x01 (CONNECT) */
            if (buf->base[3] == 0x01) { /* 'ATYP' == 0x01 (IPV4) */
                if (buf->len == 6 + 4) {
                    init_connect_command(ctx, CMD_CONNECT_IPV4,
                        *(u16_t*) (buf->base + 8), (u8_t*) (buf->base + 4), 4);
                    buf->base[1] = 0x00;
                } else {
                    XLOGW("socks5 IPV4 request packet len (%d) error.", buf->len);
                    buf->base[1] = 0x01;
                }
            } else if (buf->base[3] == 0x03) { /* 'ATYP' == 0x03 (DOMAINNAME) */
                u32_t l = buf->base[4] & 0xff;

                if (l < MAX_DOMAIN_LEN && buf->len == 6 + 1 + l) {
                    u16_t port = *(u16_t*) (buf->base + l + 5);

                    buf->base[5 + l] = 0; /* make domain name null-terminated. */
                    init_connect_command(ctx, CMD_CONNECT_DOMAIN,
                        port, (u8_t*) (buf->base + 5), l + 1);
                    buf->base[1] = 0x00;
                } else {
                    XLOGW("socks5 request packet len error, domain len %d.", l);
                    buf->base[1] = 0x01;
                }
            } else if (buf->base[3] == 0x04) { /* 'ATYP' == 0x04 (IPV6) */
                if (buf->len == 6 + 16) {
                    init_connect_command(ctx, CMD_CONNECT_IPV6,
                        *(u16_t*) (buf->base + 20), (u8_t*) (buf->base + 4), 16);
                    buf->base[1] = 0x00;
                } else {
                    XLOGW("socks5 IPV6 request packet len (%d) error.", buf->len);
                    buf->base[1] = 0x01;
                }
            } else {
                XLOGW("unsupported socks5 address type %d.", buf->base[3]);
                buf->base[1] = 0x08;
            }

            if (buf->base[1] == 0x00) { /* no error */
                if (connect_xserver(ctx) == 0) {
                    /* assume that proxy server was connected successfully. */

                    /* zero BIND.ADDR and BIND.PORT. uv_tcp_getsockname() maybe better. */
                    memset(buf->base + 4, 0, 6);

                    /* stop reading from socks client until proxy server connected. */
                    uv_read_stop((uv_stream_t*) &ctx->xclient.t.io);

                    buf->base[3] = 1; /* set response 'ATYP' to IPV4 */
                    buf->len = 6 + 4;
                    return 0;
                }
                /* connect proxy server failed immediately. */
                buf->base[1] = 0x03;
            }

        } else if (buf->base[1] == 0x03) { /* 'CMD' == 0x03 (UDP ASSOCIATE) */
            if (xclient.n_uconnect) {
                union {
                    struct sockaddr     vx;
                    struct sockaddr_in  v4;
                    struct sockaddr_in6 v6;
                } addr;
                int len = sizeof(addr);

                if (buf->base[3] == 0x01) { /* 'ATYP' == 0x01 (IPV4) */
                    if (buf->len == 6 + 4) {
                        /* record 'DST.ADDR', 'DST.PORT' and 'addr', TODO. */
                        buf->base[1] = 0x00;
                    } else {
                        XLOGW("socks5 IPV4 udp request packet len (%d) error.", buf->len);
                        buf->base[1] = 0x01;
                    }
                } else if (buf->base[3] == 0x04) { /* 'ATYP' == 0x04 (IPV6) */
                    if (buf->len == 6 + 16) {
                        /* record 'DST.ADDR', 'DST.PORT' and 'addr', TODO. */
                        buf->base[1] = 0x00;
                    } else {
                        XLOGW("socks5 IPV6 udp request packet len (%d) error.", buf->len);
                        buf->base[1] = 0x01;
                    }
                } else {
                    XLOGW("unsupported socks5 udp address type %d.", buf->base[3]);
                    buf->base[1] = 0x08;
                }

                if (buf->base[1] == 0x00) {
                    /* no error, reply the address and port which udp relay server listen at. */
                    uv_tcp_getsockname(&ctx->xclient.t.io, &addr.vx, &len);

                    switch (addr.vx.sa_family) {
                    case AF_INET:
                        buf->base[3] = 0x01; /* set response 'ATYP' to IPV4 */
                        memcpy(buf->base + 4, &addr.v4.sin_addr, 4);
                        memcpy(buf->base + 8, &addr.v4.sin_port, 2);
                        buf->len = 6 + 4;
                        break;
                    case AF_INET6:
                        buf->base[3] = 0x04; /* set response 'ATYP' to IPV6 */
                        memcpy(buf->base + 4, &addr.v6.sin6_addr, 16);
                        memcpy(buf->base + 20, &addr.v6.sin6_port, 2);
                        buf->len = 6 + 16;
                        break;
                    default:
                        XLOGE("uv_tcp_getsockname failed.");
                        return -1;
                    }
                    ctx->stage = STAGE_NOOP;
                    return 0;
                }

            } else {
                XLOGW("socks5 udp relay not enabled.");
                buf->base[1] = 0x01;
            }

        } else {
            /* 'BIND' not supported. */
            XLOGW("unsupported socks5 command %d.", buf->base[1]);
            buf->base[1] = 0x07;
        }

        return 1;
    }

    /* can't reach here. */
    XLOGE("unexpected state happen.");
    return -1;
}

/* override */ void on_xclient_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    xclient_ctx_t* ctx = stream->data;
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        uv_buf_t wbuf;

        wbuf.base = buf->base;
        wbuf.len = nread;

        iob->wreq.data = ctx;

        if (ctx->stage == STAGE_FORWARD) {
            XLOGD("%zd bytes from socks client, to proxy server.", nread);

            xclient.cryptox.encrypt(&ctx->ectx, (u8_t*) wbuf.base, wbuf.len);

            uv_write(&iob->wreq, (uv_stream_t*) &ctx->io_xserver,
                &wbuf, 1, on_xserver_write);

            if (uv_stream_get_write_queue_size(
                    (uv_stream_t*) &ctx->io_xserver) > MAX_WQUEUE_SIZE) {
                XLOGD("proxy server write queue pending.");

                /* stop reading from SOCKS client until proxy server write queue cleared. */
                uv_read_stop(stream);
                ctx->xclient_blocked = 1;
            }
            /* 'iob' free later. */
            return;
        }

        if (ctx->stage != STAGE_NOOP) {
            switch (socks_handshake(ctx, &wbuf)) {
            case 0:
                /* write response to socks client. */
                uv_write(&iob->wreq, stream, &wbuf, 1, on_xclient_write);
                /* 'iob' free later. */
                return;
            case 1:
                /* write response to socks client. */
                uv_write(&iob->wreq, stream, &wbuf, 1, on_xclient_write);
                /* close this connection. */
                uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
                uv_close((uv_handle_t*) stream, on_io_closed);
                /* 'iob' free later. */
                return;
            case -1:
                /* error packet from client, close connection. */
                uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
                uv_close((uv_handle_t*) stream, on_io_closed);
                break;
            }
        }

    } else if (nread < 0) {
        XLOGD("disconnected from socks client: %s, stage %d.",
            uv_err_name((int) nread), ctx->stage);

        if (ctx->stage == STAGE_NOOP) {
            /* terminate associated udp connection, TODO. */
        }
        uv_close((uv_handle_t*) &ctx->io_xserver, on_io_closed);
        uv_close((uv_handle_t*) stream, on_io_closed);

        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

static void on_sclient_connect(uv_stream_t* stream, int status)
{
    xclient_ctx_t* ctx;

    if (status < 0) {
        XLOGE("new connection error: %s.", uv_strerror(status));
        return;
    }
    ctx = xlist_alloc_back(&xclient.xclient_ctxs);

    uv_tcp_init(xclient.loop, &ctx->xclient.t.io);

    ctx->xclient.t.io.data = ctx;
    ctx->io_xserver.data = ctx;
    ctx->pending_iob = NULL;
    ctx->ref_count = 1;
    ctx->is_udp = 0;
    ctx->xclient_blocked = 0;
    ctx->xserver_blocked = 0;
    ctx->stage = STAGE_INIT;

    if (uv_accept(stream, (uv_stream_t*) &ctx->xclient.t.io) == 0) {
        XLOGD("socks client connected.");
        uv_tcp_init(xclient.loop, &ctx->io_xserver);
        uv_read_start((uv_stream_t*) &ctx->xclient.t.io, on_iobuf_alloc, on_xclient_read);
        /* keepalive with socks client. */
        uv_tcp_keepalive(&ctx->xclient.t.io, 1, KEEPIDLE_TIME);
        /* 'ctx->io_xserver' need to be closed, increase refcount. */
        ctx->ref_count = 2;
    } else {
        XLOGE("uv_accept failed.");
        uv_close((uv_handle_t*) &ctx->xclient.t.io, on_io_closed);
    }
}

static void on_udp_sclient_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xclient.io_buffers);

    /* leave 'sizeof(udp_cmd_t) - 4' bytes space at the beginning. */
    buf->base = iob->buffer + sizeof(udp_cmd_t) - 4;
    buf->len = MAX_SOCKBUF_SIZE - sizeof(udp_cmd_t) + 4;
}

static void on_udp_sclient_read(uv_udp_t* io, ssize_t nread, const uv_buf_t* buf,
        const struct sockaddr* addr, unsigned int flags)
{
    io_buf_t* iob = xcontainer_of(buf->base - sizeof(udp_cmd_t) + 4, io_buf_t, buffer);

    /* udp_cmd_t header:
     * +-----+------+-----+----+----------+----------+----------+
     * | TAG | ALEN | LEN | ID | DST.ADDR | DST.PORT |   DATA   |
     * +-----+------+-----+----+----------+----------+----------+
     * |  1  |  1   |  2  |  4 | Variable |    2     | Variable |
     * +-----+------+-----+----+----------+----------+----------|
     * SOCKS5 UDP client request header:
     *     +-----+------+------+----------+----------+----------+
     *     | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     *     +-----+------+------+----------+----------+----------+
     *  4  |  2  |  1   |  1   | Variable |    2     | Variable |
     *     +-----+------+------+----------+----------+----------+
     * ATYP:
     *   X'01' IP V4 address
     *   X'03' DOMAINNAME
     *   X'04' IP V6 address
     */

    if (nread < 7 || (buf->base[0] | buf->base[1])) { /* 'RSV' != 0x0000 */
        XLOGD("invalid udp packet from socks5 client (%zd/%04x).", nread,
            *(u16_t*) buf->base);

    } else if (flags & UV_UDP_PARTIAL) {
        XLOGW("socks5 udp packet too large (> %u), drop it.", buf->len);

    } else if (buf->base[2]) { /* 'FRAG' != 0x00 */
        XLOGW("socks5 udp packet with fragment is not supported.");

    } else if (buf->base[3] == 0x01) { /* 'ATYP' == 0x01 (IPV4) */

        /* 'addr' should be recorded by 'UDP ASSOCIATE' ever, TODO. */
        if (nread >= 4 + 4 + 2) {
            udp_cmd_t* cmd = (udp_cmd_t*) iob->buffer;

            cmd->flag = xclient.utimeo;
            cmd->alen = 4;
            cmd->len = htons((u16_t) (nread - 4));
            cmd->id = get_udp_packet_id(addr);

            iob->len = (u32_t) (nread - 4 + sizeof(udp_cmd_t));

            XLOGD("%u udp bytes from socks5 client, to proxy server, id %x.",
                iob->len, cmd->id);
            send_udp_packet(iob);
            /* 'iob' free later. */
            return;
        }

        XLOGW("socks5 IPV4 udp packet len (%zd) error.", nread);

    } else if (buf->base[3] == 0x04) { /* 'ATYP' == 0x04 (IPV6) */

        /* 'addr' should be recorded by 'UDP ASSOCIATE' ever, TODO. */
        if (nread >= 4 + 16 + 2) {
            udp_cmd_t* cmd = (udp_cmd_t*) iob->buffer;

            cmd->flag = xclient.utimeo;
            cmd->alen = 16;
            cmd->len = htons((u16_t) (nread - 4));
            cmd->id = get_udp_packet_id(addr);

            iob->len = (u32_t) (nread - 4 + sizeof(udp_cmd_t));

            XLOGD("%u udp bytes from socks5 client, to proxy server, id %x.",
                iob->len, cmd->id);
            send_udp_packet(iob);
            /* 'iob' free later. */
            return;
        }

        XLOGW("socks5 IPV6 udp packet len (%zd) error.", nread);

    } else {
        XLOGW("unsupported socks5 udp packet address type: %d.", buf->base[3]);
    }

    xlist_erase(&xclient.io_buffers, xlist_value_iter(iob));
}

/* override */ void recv_udp_packet(udp_cmd_t* cmd)
{
    const struct sockaddr* addr = get_udp_packet_saddr(cmd->id);
    uv_buf_t wbuf;

    if (!addr) {
        XLOGW("udp packet id (%x) not found.", cmd->id);
        return;
    }
    /* zero 'RSV', 'FRAG' and 'ATYP'. */
    cmd->id = 0;
    /* set 'ATYP'. */
    ((char*) cmd)[4 + 3] = cmd->alen == 4 ? 0x01 : 0x04;

    wbuf.base = (char*) cmd + 4;
    wbuf.len = ntohs(cmd->len) + 4;

    XLOGD("%u udp bytes to socks5 client (%s).", wbuf.len, addr_to_str(addr));

    if (uv_udp_try_send(&io_usserver, &wbuf, 1, addr) < 0) {
        XLOGD("send udp packet to socks5 client failed.");
    }
}

static void usage(const char* s)
{
    fprintf(stderr, "trp %s libuv %s, usage: %s [option]...\n", version_string(), uv_version_string(), s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -x <address>  proxy server connect to. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -b <address>  SOCKS4/SOCKS5 server listen at. (default: 127.0.0.1:%d)\n", DEF_SSERVER_PORT);
    fprintf(stderr, "  -d <devid>    device id (1~16 bytes string) of client connect to. (default: not connect client)\n");
    fprintf(stderr, "  -k <password> crypto password with proxy server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> crypto password with client. (default: none)\n");
    fprintf(stderr, "  -m <method>   crypto method with proxy server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   crypto method with client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -u <number>   set the number of UDP-over-TCP connection pools. (default: 0)\n");
    fprintf(stderr, "  -O <number>   set UDP connection timeout seconds. (default: %d)\n", UDPCONN_TIMEO);
#ifndef _WIN32
    fprintf(stderr, "  -n <number>   set max number of open files.\n");
#endif
    fprintf(stderr, "  -l <path>     write output to file. (default: write to STDOUT)\n");
    fprintf(stderr, "  -L <path>     write output to file and run as daemon. (default: write to STDOUT)\n");
    fprintf(stderr, "  -C <path>     set config file path and section. (default: trp.ini)\n");
    fprintf(stderr, "                - section can be specified after colon (default: trp.ini:socks)\n");
    fprintf(stderr, "  -v            output verbosely.\n");
    fprintf(stderr, "  -V            output version string.\n");
    fprintf(stderr, "  -h            print this help message.\n");
    fprintf(stderr, "[address]:\n");
    fprintf(stderr, "  1.2.3.4:8080  IPV4 string with port.\n");
    fprintf(stderr, "  1.2.3.4       IPV4 string with default port.\n");
    fprintf(stderr, "  :8080         IPV4 string with default address.\n");
    fprintf(stderr, "  [::1]:8080    IPV6 string with port.\n");
    fprintf(stderr, "  [::1]         IPV6 string with default port.\n");
    fprintf(stderr, "  []:8080       IPV6 string with default address.\n");
    fprintf(stderr, "  []            IPV6 string with default address and port.\n");
    fprintf(stderr, "  abc.com:8080  DOMAIN string with port.\n");
    fprintf(stderr, "  abc.com       DOMAIN string with default port.\n");
    fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
    uv_tcp_t io_sserver; /* socks server listen io */
    union { struct sockaddr x; struct sockaddr_in6 d; } saddr;
    char* cfg_path = NULL;
    const char* cfg_sec = "socks";
    const char* xserver_str = "127.0.0.1";
    const char* sserver_str = "127.0.0.1";
    const char* devid_str = NULL;
    const char* logfile = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int daemonize = 0;
    int cfg_specified = 0;
#ifdef _WIN32
    int is_childproc = 0;
#else
    int nofile = 0;
#endif
    int utimeo = UDPCONN_TIMEO;
    int nconnect = 0;
    int verbose = 0;
    int error;
    int i;

    for (i = 1; i < argc; ++i) {
        char* opt = argv[i];
        char* arg;

        if (opt[0] != '-') {
            /* argument only. (opt) */
            fprintf(stderr, "%s: invalid parameter [%s].\n", argv[0], opt);
            return 1;
        }

        if (opt[1] != '-') {
            opt = opt + 1;

            /* short option without argument. (-opt[0]) */
            switch (opt[0]) {
            case 'v': verbose = 1; continue;
            case 'V':
                fprintf(stderr, "trp %s libuv %s.\n", version_string(), uv_version_string());
                return 1;
            case 'h':
                usage(argv[0]);
                return 1;
            case '\0':
                fprintf(stderr, "%s: invalid parameter [-].\n", argv[0]);
                return 1;
            }

            arg = opt[1] ? opt + 1 : (++i < argc ? argv[i] : NULL);
            if (!arg) {
                fprintf(stderr, "%s: invalid parameter [-%c].\n", argv[0], opt[0]);
                return 1;
            }

            /* short option with argument. (-opt[0] arg) */
            switch (opt[0]) {
            case 'x': xserver_str = arg; continue;
            case 'b': sserver_str = arg; continue;
            case 'd':   devid_str = arg; continue;
            case 'm':      method = atoi(arg); continue;
            case 'M':     methodx = atoi(arg); continue;
            case 'k':      passwd = arg; continue;
            case 'K':     passwdx = arg; continue;
            case 'u':    nconnect = atoi(arg); continue;
            case 'O':      utimeo = atoi(arg); continue;
#ifndef _WIN32
            case 'n':      nofile = atoi(arg); continue;
#endif
            case 'l':     logfile = arg;     daemonize = 0; continue;
            case 'L':     logfile = arg;     daemonize = 1; continue;
            case 'C':    cfg_path = arg; cfg_specified = 1; continue;
            }

            fprintf(stderr, "%s: invalid parameter [-%c %s].\n", argv[0], opt[0], arg);
            return 1;
        }
        opt = opt + 2;

        /* long option without argument. (--opt) */
#ifdef _WIN32
        if (!strcmp(opt, "child")) { /* --child is for internal use only */
            is_childproc = 1;
            continue;
        }
#endif

        arg = ++i < argc ? argv[i] : NULL;
        if (!arg) {
            fprintf(stderr, "%s: invalid parameter [--%s].\n", argv[0], opt);
            return 1;
        }

        /* long option with argument. (--opt arg) */

        fprintf(stderr, "%s: invalid parameter [--%s %s].\n", argv[0], opt, arg);
        return 1;
    }

    xlog_init(NULL); /* output to STDOUT first */

    i = 0;
    parse_config_str(&cfg_path, &cfg_sec);
    error = load_config_file(cfg_path, cfg_sec);
    if (error < 0) {
        if (cfg_specified) {
            XLOGE("open config file (%s) failed, exit.", cfg_path);
            return 1;
        }
    } else if (error > 0) {
        XLOGE("error at config file %s:%d, ignore configs.", cfg_path, error);
    } else {
        config_item_t* item = NULL;

        while (!!(item = get_config_item(item))) {
            if (!item->name[0] || !item->value[0]) {
                XLOGW("invalid config item (%s=%s), ignore.", item->name, item->value);
                continue;
            } else if (!strcmp(item->name, "v")) { verbose = atoi(item->value);
            } else if (!strcmp(item->name, "x")) { xserver_str = item->value;
            } else if (!strcmp(item->name, "b")) { sserver_str = item->value;
            } else if (!strcmp(item->name, "d")) { devid_str = item->value;
            } else if (!strcmp(item->name, "m")) { method = atoi(item->value);
            } else if (!strcmp(item->name, "M")) { methodx = atoi(item->value);
            } else if (!strcmp(item->name, "k")) { passwd = item->value;
            } else if (!strcmp(item->name, "K")) { passwdx = item->value;
            } else if (!strcmp(item->name, "u")) { nconnect = atoi(item->value);
            } else if (!strcmp(item->name, "O")) { utimeo = atoi(item->value);
#ifndef _WIN32
            } else if (!strcmp(item->name, "n")) { nofile = atoi(item->value);
#endif
            } else if (!strcmp(item->name, "l")) { logfile = item->value; daemonize = 0;
            } else if (!strcmp(item->name, "L")) { logfile = item->value; daemonize = 1;
            } else {
                XLOGW("invalid config item name (%s), ignore.", item->name);
                continue;
            }
            ++i;
        }
    }

    if (logfile) {
        XLOGI("switch output to file: %s...", logfile);
        if (xlog_init(logfile) != 0) {
            XLOGE("open logfile failed, switch to stdout.");
        }
    }

#ifdef _WIN32
    if (daemonize && !is_childproc) {
        xlog_exit(); /* close log file */
        if (daemon(argc, argv) != 0) {
            xlog_init(logfile); /* reopen log file when daemon failed */
            XLOGE("run as daemon failed: %u", GetLastError());
        }
    }
#else
    if (daemonize && daemon(1, 0) != 0) {
        XLOGE("run as daemon failed: %s.", strerror(errno));
    }
#endif
    XLOGI("current version %s, libuv %s.", version_string(), uv_version_string());
    if (!verbose) {
        xlog_ctrl(XLOG_INFO, 0, 0);
    } else {
        XLOGI("enable verbose output.");
    }
    if (i > 0) {
        XLOGI("load %d item(s) from config file (%s:%s).", i, cfg_path, cfg_sec);
    }
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);

    if (nofile > 1024) {
        struct rlimit limit = { nofile, nofile };

        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            XLOGW("set NOFILE limit to %d failed: %s.", nofile, strerror(errno));
        } else {
            XLOGI("set NOFILE limit to %d.", nofile);
        }
    }
#endif
    seed_rand((u32_t) time(NULL));

    xclient_private_init();
    xclient.loop = uv_default_loop();

    if (nconnect < 0 || nconnect > 1024) {
        XLOGW("invalid connection pool size (%d), reset to 1.", nconnect);
        nconnect = 1;
    }

    if (utimeo <= 0 || utimeo > MAX_UDPCONN_TIMEO) {
        XLOGW("invalid UDP connection timeout (%d), reset to %d.",
            utimeo, UDPCONN_TIMEO);
        utimeo = UDPCONN_TIMEO;
    }
    xclient.utimeo = (u8_t) utimeo;

    if (devid_str && str_to_devid(xclient.device_id, devid_str) != 0) {
        XLOGE("invalid device id string (%s).", devid_str);
        goto end;
    }

    if (passwd) {
        derive_key(xclient.crypto_key, passwd);
    } else {
        XLOGI("password not set, disable crypto with proxy server.");
        method = CRYPTO_NONE;
    }
    if (devid_str) {
        if (passwdx) {
            derive_key(xclient.cryptox_key, passwdx);
        } else {
            XLOGI("PASSWORD (-K) not set, disable crypto with client.");
            methodx = CRYPTO_NONE;
        }
    } else {
        if (passwdx) {
            XLOGI("device id not set, ignore PASSWORD (-K).");
        }
        methodx = method;
        memcpy(xclient.cryptox_key, xclient.crypto_key, 16);
    }

    if (crypto_init(&xclient.crypto, method) != 0) {
        XLOGE("invalid crypto method (%d).", method);
        goto end;
    }
    if (crypto_init(&xclient.cryptox, methodx) != 0) {
        XLOGE("invalid crypto METHOD (%d).", methodx);
        goto end;
    }
    XLOGI("crypto method %d, METHOD %d.", method, methodx);

    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xclient.xserver_addr.x) != 0) {
        struct sockaddr_dm dm;

        if (parse_domain_str(xserver_str, DEF_XSERVER_PORT, &dm) != 0
                || resolve_domain_sync(xclient.loop, &dm, &xclient.xserver_addr.x) != 0) {
            XLOGE("invalid proxy server address (%s).", xserver_str);
            goto end;
        }
    }

    if (parse_ip_str(sserver_str, DEF_SSERVER_PORT, &saddr.x) != 0) {
        XLOGE("invalid socks5 server address (%s).", sserver_str);
        goto end;
    }

    uv_tcp_init(xclient.loop, &io_sserver);

    error = uv_tcp_bind(&io_sserver, &saddr.x, 0);
    if (error) {
        XLOGE("tcp bind (%s) failed: %s.", addr_to_str(&saddr),
            uv_strerror(error));
        goto end;
    }
    error = uv_listen((uv_stream_t*) &io_sserver, LISTEN_BACKLOG, on_sclient_connect);
    if (error) {
        XLOGE("tcp listen (%s) failed: %s.", addr_to_str(&saddr),
            uv_strerror(error));
        goto end;
    }

    if (nconnect) {
        XLOGI("enable UDP relay, connections %d, timeout %d.", nconnect, utimeo);
        uv_udp_init(xclient.loop, &io_usserver);
        /* start socks5 udp listen io. */
        error = uv_udp_bind(&io_usserver, &saddr.x, 0);
        if (error) {
            XLOGE("udp bind (%s) failed: %s.", addr_to_str(&saddr),
                uv_strerror(error));
            goto end;
        }
        error = uv_udp_recv_start(&io_usserver, on_udp_sclient_rbuf_alloc,
                    on_udp_sclient_read);
        if (error) {
            XLOGE("udp listen (%s) failed: %s.", addr_to_str(&saddr),
                uv_strerror(error));
            goto end;
        }
        xclient.n_uconnect = nconnect;
    }

    xlist_init(&xclient.xclient_ctxs, sizeof(xclient_ctx_t), NULL);
    xlist_init(&xclient.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);

    XLOGI("proxy server: %s.", addr_to_str(&xclient.xserver_addr));
    if (devid_str) {
        XLOGI("to device id: %s.", devid_to_str(xclient.device_id));
    }
    XLOGI("SOCKS4/SOCKS5 server listen at %s...", addr_to_str(&saddr));
    uv_run(xclient.loop, UV_RUN_DEFAULT);

    xlist_destroy(&xclient.io_buffers);
    xlist_destroy(&xclient.xclient_ctxs);
end:
    XLOGI("end of loop.");
    xclient_private_destroy();
    xlog_exit();

    return 0;
}