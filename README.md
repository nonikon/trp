# TRP - Tiny Reverse Proxy
## Feature
- SOCKS5 TCP/UDP proxy and SOCKS4/SOCKS4a TCP proxy.
- Linux iptable redirect (TCP).
- TCP/UDP port mapping.

## Build
If you already have libuv installed on your system, use the following command:
```bash
mkdir build
cd build
cmake .. -DLIBUV_EMBEDDED=OFF
cmake --build .
```
Otherwise, you will need to download the libuv source code and extract it first, such as:
```bash
wget https://dist.libuv.org/dist/v1.46.0/libuv-v1.46.0.tar.gz
tar xf libuv-v1.46.0.tar.gz
mkdir build
cd build
cmake .. -DLIBUV_SRC_PATH=../libuv-v1.46.0
cmake --build .
```
You can also choose to download the x86_64 windows and linux binaries directly from [release](https://github.com/nonikon/trp/releases) page.

## Architecture
```text
                 +--------------+      +--------------+
APPLICATION ---> | proxy-client | ---> | proxy-server | ---> REMOTE
                 +--------------+      |      |       |
                 socks.c/tunnel.c      |      v       |      +--------+
                                       |    server  - | ---> | client | ---> REMOTE
                                       +--------------+      +--------+
                                           server.c           client.c
```

## Example Usage
First, start `server` on a host which has a public IP address:
```bash
./trp-server -s 0.0.0.0:1111 -x 0.0.0.0:2222 -k KEY_OF_SERVER
```
Second, start `client` on a host that can access to `server`: (Assuming the above `server` IP address is 1.2.3.4)
```bash
./trp-client -s 1.2.3.4:1111 -k KEY_OF_SERVER -d DEVID_OF_CLIENT -K KEY_OF_CLIENT
```
Finally, start `proxy-client` locally (should have access to the `server`) on demand (see examples below).

### Access the network through `server` by SOCKS4/SOCKS5 protocol
- Start a socks server locally (listen at 127.0.0.1:8080):
    ```bash
    ./trp-socks -b :8080 -x 1.2.3.4:2222 -k KEY_OF_SERVER
    ```
- Then you can use an application that supports SOCKS protocol to access the network through `server` (1.2.3.4), such as `curl`:
    ```bash
    curl -x socks5://127.0.0.1:8080 https://www.google.com
    ```
- That is:
    ```text
              +--------------+      +--------+
    curl ---> | proxy-client | ---> | server | ---> www.google.com:443
              +--------------+      +--------+
    ```

### Access the network through `client` by SOCKS4/SOCKS5 protocol
- Start a socks server locally (listen at 127.0.0.1:8080):
    ```bash
    ./trp-socks -b :8080 -x 1.2.3.4:2222 -k KEY_OF_SERVER -d DEVID_OF_CLIENT -K KEY_OF_CLIENT
    ```
- Then you can use an application that supports SOCKS protocol to access the network through `client` (DEVID_OF_CLIENT), such as `curl`:
    ```bash
    curl -x socks5://127.0.0.1:8080 https://www.google.com
    ```
- That is:
    ```text
              +--------------+      +--------+      +--------+
    curl ---> | proxy-client | ---> | server | ---> | client | ---> www.google.com:443
              +--------------+      +--------+      +--------+
    ```

### Access the network through `server` by port mapping
- Start a tunnel server locally (listen at 127.0.0.1:8000):
    ```bash
    ./trp-tunnel -b :8000 -t 192.168.0.1:22 -x 1.2.3.4:2222 -k KEY_OF_SERVER
    ```
- Then you can access the SSH service of 192.168.0.1 through the `server` (1.2.3.4), such as:
    ```bash
    ssh -p 8000 user@127.0.0.1
    ```
- That is:
    ```text
             +--------------+      +--------+
    ssh ---> | proxy-client | ---> | server | ---> 192.168.0.1:22
             +--------------+      +--------+
    ```

### Access the network through `client` by port mapping
- Start a tunnel server locally (listen at 127.0.0.1:8000):
    ```bash
    ./trp-tunnel -b :8000 -t :22 -x 1.2.3.4:2222 -k KEY_OF_SERVER -d DEVID_OF_CLIENT -K KEY_OF_CLIENT
    ```
- Then you can access the SSH service of `client` (DEVID_OF_CLIENT), such as:
    ```bash
    ssh -p 8000 user@127.0.0.1
    ```
- That is:
    ```text
             +--------------+      +--------+      +--------+
    ssh ---> | proxy-client | ---> | server | ---> | client | ---> 127.0.0.1:22
             +--------------+      +--------+      +--------+
    ```

### Access the network through `server` by port mapping (UDP)
- Start a tunnel server locally (UDP listen at 127.0.0.1:5353):
    ```bash
    ./trp-tunnel -b :5353 -t 8.8.8.8:53 -U 1 -x 1.2.3.4:2222 -k KEY_OF_SERVER
    ```
- Then you can do DNS resolve by `8.8.8.8` through `server` (1.2.3.4), such as:
    ```bash
    dig -p 5353 @127.0.0.1 www.google.com
    ```

### Access the network through `client` by port mapping (UDP)
- Start a tunnel server locally (UDP listen at 127.0.0.1:5353):
    ```bash
    ./trp-tunnel -b :5353 -t 8.8.8.8:53 -U 1 -x 1.2.3.4:2222 -k KEY_OF_SERVER -d DEVID_OF_CLIENT -K KEY_OF_CLIENT
    ```
- Then you can do DNS resolve by `8.8.8.8` through `client` (DEVID_OF_CLIENT), such as:
    ```bash
    dig -p 5353 @127.0.0.1 www.google.com
    ```
NOTE: Config file is supported by `-C` command option, see [trp.ini](trp.ini).

## Lisence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
