# TRP - Tiny Reverse Proxy
## Feature
- SOCKS5 TCP/UDP proxy and SOCKS4 TCP proxy.
- Linux iptable redirect (TCP).
- TCP/UDP port mapping.
## Design
```text
                                --------------         --------------
                  REMOTE <---> | proxy-server | <---> | proxy-client | <---> APPLICATION
                               |      ^       |        --------------
                               |      |       |       socks.c/tunnel.c
               --------        |      v       |
 REMOTE <---> | client | <---> |   server     |
               --------         --------------
               client.c            server.c
```
## Usage
- TODO