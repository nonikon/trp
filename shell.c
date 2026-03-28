/*
 * Copyright (C) 2026 nonikon@qq.com.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "crypto.h"
#include "xlist.h"

struct {
    io_buf_t* last_iob;
    uv_connect_t conn_req;
    uv_tty_t io_stdin;
    uv_tty_t io_stdout;
    uv_signal_t wch_watcher;
    uv_tcp_t io_xserver;
    xlist_t io_buffers; /* io_buf_t */
    crypto_t crypto;
    crypto_t cryptox;
    crypto_ctx_t ectx;
    crypto_ctx_t dctx;
    u8_t crypto_key[16];
    u8_t cryptox_key[16];
    u8_t ctrl_key[16];
    u8_t device_id[DEVICE_ID_SIZE];
    u8_t stdin_blocked;
    u8_t xserver_blocked;
    u8_t fgrnd;
    u8_t verbose;
} xshctx;

#define XLOGE(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define XLOGI(fmt, ...) \
    do { if (xshctx.verbose) fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)

#if 0
#define XLOGD(fmt, ...) \
    do { if (xshctx.verbose) fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
#define XLOGD(fmt, ...)
#endif

static void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void on_stdin_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

static void on_xserver_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xshctx.io_buffers);

    buf->base = iob->buffer;
    buf->len = MAX_SOCKBUF_SIZE;
}

static void on_stdin_rbuf_alloc(uv_handle_t* handle, size_t sg_size, uv_buf_t* buf)
{
    io_buf_t* iob = xlist_alloc_back(&xshctx.io_buffers);

    /* leave 'sizeof(pty_cmd_t)' bytes space at the beginning. */
    buf->base = iob->buffer + sizeof(pty_cmd_t);
    buf->len = MAX_SOCKBUF_SIZE - sizeof(pty_cmd_t);
}

static void on_xserver_write(uv_write_t* req, int status)
{
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (xshctx.stdin_blocked && xshctx.io_xserver.write_queue_size == 0) {
        XLOGD("Proxy server write queue cleared.");
        uv_read_start((uv_stream_t*) &xshctx.io_stdin, on_stdin_rbuf_alloc,
            on_stdin_read);
        xshctx.stdin_blocked = 0;
    }
    xlist_erase(&xshctx.io_buffers, xlist_value_iter(iob));
}

static void on_stdout_write(uv_write_t* req, int status)
{
    io_buf_t* iob = xcontainer_of(req, io_buf_t, wreq);

    if (xshctx.xserver_blocked && xshctx.io_stdout.write_queue_size == 0) {
        XLOGD("Stdout write queue cleared.");
        uv_read_start((uv_stream_t*) &xshctx.io_xserver, on_xserver_rbuf_alloc,
            on_xserver_read);
        xshctx.xserver_blocked = 0;
    }
    xlist_erase(&xshctx.io_buffers, xlist_value_iter(iob));
}

static void on_stdin_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    io_buf_t* iob = xcontainer_of(buf->base - sizeof(pty_cmd_t), io_buf_t, buffer);

    if (nread > 0) {
        pty_cmd_t* cmd = (pty_cmd_t*) iob->buffer;
        uv_buf_t wbuf;

        cmd->cmd = PTYCMD_DATA;
        cmd->__1 = 0;
        cmd->len = htons((u16_t) nread);
        cmd->__2 = 0;
        fill_pty_command_md(cmd);

        wbuf.base = iob->buffer;
        wbuf.len = sizeof(pty_cmd_t) + nread;

        XLOGD("Got %zd bytes from stdin.", nread);
        xshctx.cryptox.encrypt(&xshctx.ectx, (u8_t*) wbuf.base, (u32_t) wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &xshctx.io_xserver, &wbuf, 1,
            on_xserver_write);

        if (xshctx.io_xserver.write_queue_size > MAX_WQUEUE_SIZE) {
            uv_read_stop(stream);
            xshctx.stdin_blocked = 1;
            XLOGD("Proxy server write queue pending.");
        }
        /* 'iob' free later. */
        return;
    }

    if (nread < 0) {
        XLOGI("Disconnected from stdin: %s.", uv_err_name((int) nread));
        uv_signal_stop(&xshctx.wch_watcher);

        uv_close((uv_handle_t*) &xshctx.io_xserver, NULL);
        uv_close((uv_handle_t*) stream, NULL);
        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&xshctx.io_buffers, xlist_value_iter(iob));
}

static void recv_pty_packet(pty_cmd_t* cmd)
{
    if (!check_pty_command_md(cmd)) {
        XLOGE("Error pty packet digest.");

    } else if (cmd->cmd == PTYCMD_DATA) {
        io_buf_t* iob = xlist_alloc_back(&xshctx.io_buffers);
        uv_buf_t wbuf;

        wbuf.base = iob->buffer;
        wbuf.len = ntohs(cmd->len);
        memcpy(wbuf.base, cmd->data, wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &xshctx.io_stdout, &wbuf, 1,
            on_stdout_write);
    } else {
        XLOGE("Error packet cmd %u.", cmd->cmd);
    }
}

static int __iob_move(io_buf_t* dst, io_buf_t* src, u32_t need)
{
    if (dst->len + src->len < need) {
        memcpy(dst->buffer + dst->len, src->buffer + src->idx, src->len);
        dst->len += src->len;
        return -1;
    }
    need -= dst->len;
    memcpy(dst->buffer + dst->len, src->buffer + src->idx, need);
    dst->len += need;
    src->len -= need;
    src->idx += need;
    return 0;
}

static int fwd_xserver_packets(io_buf_t* iob)
{
    pty_cmd_t* cmd;
    u32_t need;

    if (xshctx.last_iob) {
        io_buf_t* last_iob = xshctx.last_iob;

        /* 'last_iob->idx' is always zero. */
        if (last_iob->len < sizeof(pty_cmd_t)
                && __iob_move(last_iob, iob, sizeof(pty_cmd_t)) != 0)
            return 0;

        cmd = (pty_cmd_t*) last_iob->buffer;
        need = ntohs(cmd->len) + sizeof(pty_cmd_t);

        if (need > MAX_SOCKBUF_SIZE || need < sizeof(pty_cmd_t)) {
            XLOGE("Error packet length (%u).", need);

            xshctx.last_iob = NULL;
            xlist_erase(&xshctx.io_buffers, xlist_value_iter(last_iob));
            return 0;
        }

        if (__iob_move(last_iob, iob, need) != 0)
            return 0;

        recv_pty_packet(cmd);

        xshctx.last_iob = NULL;
        xlist_erase(&xshctx.io_buffers, xlist_value_iter(last_iob));
    }

    while (iob->len > sizeof(pty_cmd_t)) {
        cmd = (pty_cmd_t*) (iob->buffer + iob->idx);
        need = ntohs(cmd->len) + sizeof(pty_cmd_t);

        if (need > MAX_SOCKBUF_SIZE || need < sizeof(pty_cmd_t)) {
            XLOGE("Error packet length (%u).", need);
            return 0;
        }
        if (iob->len < need) {
            /* udp packet need more. */
            break;
        }
        recv_pty_packet(cmd);

        iob->idx += need;
        iob->len -= need;
    }

    if (iob->len) {
        if (iob->idx) {
            memmove(iob->buffer, iob->buffer + iob->idx, iob->len);
            iob->idx = 0;
        }
        XLOGD("%u bytes left.", iob->len);

        xshctx.last_iob = iob;
        return 1;
    }

    return 0;
}

static void on_xserver_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    io_buf_t* iob = xcontainer_of(buf->base, io_buf_t, buffer);

    if (nread > 0) {
        iob->idx = 0;
        iob->len = (u32_t) nread;

        XLOGD("Got %zd bytes from proxy server.", nread);
        xshctx.cryptox.decrypt(&xshctx.dctx, (u8_t*) buf->base, (u32_t) nread);

        if (fwd_xserver_packets(iob) == 0) {
            /* 'iob' was processed totally, release now. */
            xlist_erase(&xshctx.io_buffers, xlist_value_iter(iob));
        }

        if (xshctx.io_stdout.write_queue_size > MAX_WQUEUE_SIZE) {
            uv_read_stop(stream);
            xshctx.xserver_blocked = 1;
            XLOGD("Stdout write queue pending.");
        }
        /* 'iob' free later. */
        return;
    }

    if (nread < 0) {
        XLOGI("Disconnected from proxy server: %s.", uv_err_name((int) nread));
        uv_signal_stop(&xshctx.wch_watcher);

        uv_close((uv_handle_t*) &xshctx.io_stdin, NULL);
        uv_close((uv_handle_t*) stream, NULL);
        /* 'buf->base' may be 'NULL' when 'nread' < 0. */
        if (!buf->base) return;
    }

    xlist_erase(&xshctx.io_buffers, xlist_value_iter(iob));
}

static void send_connect_command()
{
    io_buf_t* iob = xlist_alloc_back(&xshctx.io_buffers);
    u8_t* pbuf = (u8_t*) iob->buffer;
    cmd_t* cmd;
    u8_t dnonce[16];
    uv_buf_t wbuf;

    if (is_valid_devid(xshctx.device_id)) {
        /* generate and prepend iv in the first packet */
        generate_nonce(pbuf);

        cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

        cmd->tag = CMD_TAG;
        cmd->major = VERSION_MAJOR;
        cmd->minor = VERSION_MINOR;
        cmd->flag = 1 << 2; /* nodelay */
        cmd->cmd = CMD_CONNECT_CLIENT;
        cmd->len = DEVICE_ID_SIZE;

        memcpy(cmd->data, xshctx.device_id, DEVICE_ID_SIZE);

        fill_command_md(cmd);
        xshctx.crypto.init(&xshctx.ectx, xshctx.crypto_key, pbuf);
        xshctx.crypto.encrypt(&xshctx.ectx, (u8_t*) cmd, CMD_MAX_SIZE);

        pbuf += MAX_NONCE_LEN + CMD_MAX_SIZE;
    }

    /* generate and prepend iv in the first packet */
    generate_nonce(pbuf);

    cmd = (cmd_t*) (pbuf + MAX_NONCE_LEN);

    cmd->tag = CMD_TAG;
    cmd->major = VERSION_MAJOR;
    cmd->minor = VERSION_MINOR;
    cmd->flag = (1 << 2) | xshctx.fgrnd; /* nodelay */
    cmd->cmd = CMD_CONNECT_PTY;
    cmd->len = (u8_t) sizeof(xshctx.ctrl_key);
    cmd->port = 0;

    memcpy(cmd->data, xshctx.ctrl_key, sizeof(xshctx.ctrl_key));

    memcpy(dnonce, pbuf, MAX_NONCE_LEN);
    convert_nonce(dnonce);

    fill_command_md(cmd);
    xshctx.cryptox.init(&xshctx.ectx, xshctx.cryptox_key, pbuf);
    xshctx.cryptox.init(&xshctx.dctx, xshctx.cryptox_key, dnonce);
    xshctx.cryptox.encrypt(&xshctx.ectx, (u8_t*) cmd, CMD_MAX_SIZE);

    iob->len = (u32_t) (pbuf + MAX_NONCE_LEN + CMD_MAX_SIZE - (u8_t*) iob->buffer);

    wbuf.base = iob->buffer;
    wbuf.len = iob->len;

    uv_write(&iob->wreq, (uv_stream_t*) &xshctx.io_xserver, &wbuf, 1, on_xserver_write);
}

static void on_winch_signal(uv_signal_t* handle, int signum)
{
    int w, h, r;

    r = uv_tty_get_winsize(&xshctx.io_stdout, &w, &h); /* NOTE: 'stdout' is needed. */
    if (r == 0) {
        io_buf_t* iob = xlist_alloc_back(&xshctx.io_buffers);
        pty_cmd_t* cmd = (pty_cmd_t*) iob->buffer;
        uv_buf_t wbuf;

        cmd->cmd = PTYCMD_WNDSIZE;
        cmd->__1 = 0;
        cmd->len = htons(4);
        cmd->__2 = 0;
        *((u16_t*) (cmd->data + 0)) = htons((u16_t) w);
        *((u16_t*) (cmd->data + 2)) = htons((u16_t) h);
        fill_pty_command_md(cmd);

        wbuf.base = iob->buffer;
        wbuf.len = sizeof(pty_cmd_t) + 4;

        XLOGD("Update winsize %dx%d.", w, h);
        xshctx.cryptox.encrypt(&xshctx.ectx, (u8_t*) wbuf.base, (u32_t) wbuf.len);

        uv_write(&iob->wreq, (uv_stream_t*) &xshctx.io_xserver, &wbuf, 1,
            on_xserver_write);
    } else {
        XLOGI("Failed to get winsize: %s.", uv_err_name(r));
    }
}

static void on_xserver_connected(uv_connect_t* req, int status)
{
    if (status == 0) {
        XLOGI("Proxy server connected.");
        send_connect_command();
        on_winch_signal(&xshctx.wch_watcher, SIGWINCH);

        uv_read_start((uv_stream_t*) &xshctx.io_stdin, on_stdin_rbuf_alloc,
            on_stdin_read);
        uv_read_start((uv_stream_t*) &xshctx.io_xserver, on_xserver_rbuf_alloc,
            on_xserver_read);
        uv_signal_start(&xshctx.wch_watcher, on_winch_signal, SIGWINCH);

        uv_tty_set_mode(&xshctx.io_stdin, UV_TTY_MODE_RAW_VT); /* NOTE: 'stdin' and 'xx_VT' is needed. */
        /* keepalive with proxy server. */
        uv_tcp_keepalive(&xshctx.io_xserver, 1, KEEPIDLE_TIME);
        uv_tcp_nodelay(&xshctx.io_xserver, 1);
    } else {
        XLOGE("Connect proxy server failed: %s.", uv_err_name(status));
    }
}

static void show_usage(const char* s)
{
    fprintf(stderr, "trp %s libuv %s, usage: %s [option]...\n", version_string(), uv_version_string(), s);
    fprintf(stderr, "[options]:\n");
    fprintf(stderr, "  -x <address>  proxy server connect to. (default: 127.0.0.1:%d)\n", DEF_XSERVER_PORT);
    fprintf(stderr, "  -T <password> remote control password.\n");
    fprintf(stderr, "  -d <devid>    device id (1~16 bytes string) of client connect to. (default: not connect client)\n");
    fprintf(stderr, "  -k <password> crypto password with proxy server. (default: none)\n");
    fprintf(stderr, "  -K <PASSWORD> crypto password with client. (default: none)\n");
    fprintf(stderr, "  -m <method>   crypto method with proxy server, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -M <METHOD>   crypto method with client, 0 - none, 1 - chacha20, 2 - sm4ofb. (default: 1)\n");
    fprintf(stderr, "  -C <config>   set config file path and section. (default: trp.ini)\n");
    fprintf(stderr, "                section can be specified after colon. (default: trp.ini:shell)\n");
    fprintf(stderr, "  -f            show the remote terminal in the foreground (for Windows remote only).\n");
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

static int parse_args(int argc, char** argv)
{
    union {
        struct sockaddr x;
        struct sockaddr_in6 d;
    } xserver_addr;
    uv_loop_t* loop;
    char* cfg_path = NULL;
    const char* cfg_sec = "shell";
    const char* xserver_str = "127.0.0.1";
    const char* devid_str = NULL;
    const char* ctrl_passwd = NULL;
    const char* passwd = NULL;
    const char* passwdx = NULL;
    int method = CRYPTO_CHACHA20;
    int methodx = CRYPTO_CHACHA20;
    int cfg_specified = 0;
    int fgrnd = 0;
    int verbose = 0;
    int ec, i;

    for (i = 1; i < argc; ++i) {
        char* opt = argv[i];
        char* arg;

        if (opt[0] != '-') {
            /* argument only. (opt) */
            XLOGE("Invalid parameter [%s].", opt);
            return 1;
        }

        if (opt[1] != '-') {
            opt = opt + 1;

            /* short option without argument. (-opt[0]) */
            switch (opt[0]) {
            case 'f':   fgrnd = 1; continue;
            case 'v': verbose = 1; continue;
            case 'V':
                XLOGE("trp %s libuv %s.", version_string(), uv_version_string());
                return 1;
            case 'h':
                show_usage(argv[0]);
                return 1;
            case '\0':
                XLOGE("Invalid parameter [-].");
                return 1;
            }

            arg = opt[1] ? opt + 1 : (++i < argc ? argv[i] : NULL);
            if (!arg) {
                XLOGE("Invalid parameter [-%c].", opt[0]);
                return 1;
            }

            /* short option with argument. (-opt[0] arg) */
            switch (opt[0]) {
            case 'x': xserver_str = arg; continue;
            case 'T': ctrl_passwd = arg; continue;
            case 'd':   devid_str = arg; continue;
            case 'm':      method = atoi(arg); continue;
            case 'M':     methodx = atoi(arg); continue;
            case 'k':      passwd = arg; continue;
            case 'K':     passwdx = arg; continue;
            case 'C':    cfg_path = arg; cfg_specified = 1; continue;
            }

            XLOGE("Invalid parameter [-%c %s].", opt[0], arg);
            return 1;
        }
        opt = opt + 2;

        /* long option without argument. (--opt) */
        arg = ++i < argc ? argv[i] : NULL;
        if (!arg) {
            XLOGE("Invalid parameter [--%s].", opt);
            return 1;
        }

        /* long option with argument. (--opt arg) */

        XLOGE("Invalid parameter [--%s %s].", opt, arg);
        return 1;
    }

    i = 0;
    parse_config_str(&cfg_path, &cfg_sec);
    ec = load_config_file(cfg_path, cfg_sec);
    if (ec < 0) {
        if (cfg_specified) {
            XLOGE("Open config file (%s) failed, exit.", cfg_path);
            return 1;
        }
    } else if (ec > 0) {
        XLOGE("Error at config file %s:%d, ignore configs.", cfg_path, ec);
    } else {
        config_item_t* item = NULL;

        while (!!(item = get_config_item(item))) {
            if (!item->name[0] || !item->value[0]) {
                XLOGE("Invalid config item (%s=%s), ignore.", item->name, item->value);
                continue;
            } else if (!strcmp(item->name, "v")) { fgrnd = atoi(item->value);
            } else if (!strcmp(item->name, "v")) { verbose = atoi(item->value);
            } else if (!strcmp(item->name, "x")) { xserver_str = item->value;
            } else if (!strcmp(item->name, "T")) { ctrl_passwd = item->value;
            } else if (!strcmp(item->name, "d")) { devid_str = item->value;
            } else if (!strcmp(item->name, "m")) { method = atoi(item->value);
            } else if (!strcmp(item->name, "M")) { methodx = atoi(item->value);
            } else if (!strcmp(item->name, "k")) { passwd = item->value;
            } else if (!strcmp(item->name, "K")) { passwdx = item->value;
            } else {
                XLOGE("Invalid config item name (%s), ignore.", item->name);
                continue;
            }
            ++i;
        }
    }

    if (fgrnd) {
        xshctx.fgrnd = 1;
    }
    if (verbose) {
        xshctx.verbose = 1;
    }
    XLOGI("Current version %s, libuv %s.", version_string(), uv_version_string());
    if (i > 0) {
        XLOGI("Load %d item(s) from config file (%s:%s).", i, cfg_path, cfg_sec);
    }
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    seed_rand((u32_t) time(NULL));

    if (!ctrl_passwd) {
        XLOGE("Control password (-T) not set, exit.");
        return 1;
    }
    derive_key(xshctx.ctrl_key, ctrl_passwd);

    if (passwd) {
        derive_key(xshctx.crypto_key, passwd);
    } else {
        XLOGI("Password not set, disable crypto with proxy server.");
        method = CRYPTO_NONE;
    }
    if (devid_str) {
        if (str_to_devid(xshctx.device_id, devid_str) != 0) {
            XLOGE("Invalid device id string (%s).", devid_str);
            return 1;
        }
        if (passwdx) {
            derive_key(xshctx.cryptox_key, passwdx);
        } else {
            XLOGI("PASSWORD (-K) not set, disable crypto with client.");
            methodx = CRYPTO_NONE;
        }
        XLOGI("Device id %s.", devid_str);
    } else {
        if (passwdx) {
            XLOGI("Device id not set, ignore PASSWORD (-K).");
        }
        methodx = method;
        memcpy(xshctx.cryptox_key, xshctx.crypto_key, 16);
    }

    if (crypto_init(&xshctx.crypto, method) != 0) {
        XLOGE("Invalid crypto method (%d).", method);
        return 1;
    }
    if (crypto_init(&xshctx.cryptox, methodx) != 0) {
        XLOGE("Invalid crypto METHOD (%d).", methodx);
        return 1;
    }
    XLOGI("Crypto method %d, METHOD %d.", method, methodx);

    loop = uv_default_loop();

    if (parse_ip_str(xserver_str, DEF_XSERVER_PORT, &xserver_addr.x) != 0) {
        struct sockaddr_dm dm;

        if (parse_domain_str(xserver_str, DEF_XSERVER_PORT, &dm) != 0) {
            XLOGE("Invalid proxy server address (%s).", xserver_str);
            return 1;
        }
        if (resolve_domain_sync(loop, &dm, &xserver_addr.x) != 0) {
            XLOGE("Resolve domain (%s) failed.", xserver_str);
            return 1;
        }
    }

    xlist_init(&xshctx.io_buffers, sizeof(io_buf_t) + MAX_SOCKBUF_SIZE, NULL);

    ec = uv_tty_init(loop, &xshctx.io_stdin, 0, 0);
    if (ec != 0) {
        XLOGE("uv_tty_init stdin failed: %s.", uv_err_name(ec));
        return 1;
    }
    ec = uv_tty_init(loop, &xshctx.io_stdout, 1, 0);
    if (ec != 0) {
        XLOGE("uv_tty_init stdout failed: %s.", uv_err_name(ec));
        return 1;
    }
    uv_signal_init(loop, &xshctx.wch_watcher);
    uv_tcp_init(loop, &xshctx.io_xserver);
    XLOGI("Connecting porxy server %s...", addr_to_str(&xserver_addr));

    ec = uv_tcp_connect(&xshctx.conn_req, &xshctx.io_xserver, &xserver_addr.x,
            on_xserver_connected);
    if (ec != 0) {
        XLOGE("Connect proxy server failed: %s.", uv_err_name(ec));
    }
    return 0;
}

int main(int argc, char** argv)
{
    if (parse_args(argc, argv) == 0) {
        uv_run(uv_default_loop(), UV_RUN_DEFAULT);
        uv_tty_reset_mode();
    }
    return 0;
}
