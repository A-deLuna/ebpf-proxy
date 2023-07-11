# eBPF sample proxy

A simple implementation of an eBPF TCP proxy in C using `SOCK_HASH`.


## Overview
`src/parser.c` is the eBPF program. It declares a `BPF_MAP_TYPE_SOCKHASH`
map with two entries. Two functions are implemented and are annotated to be placed
in sections named `sk_skb/stream_parser` and `sk_skb/stream_verdict`. These
sections are meaningful to `libbpf`.

The functions themselves are straightforward. The parser function returns the lenght
of the message to be proxied. The verdict function extracts the
SOCKHASH key from the `__sk_buff struct`. The key consists of a 4 tuple
of `(src_ip, dst_ip, src_port and dst_port)` represented by the `socket_key` struct we
defined. 

`src/main.c` is the user process entrypoint. It uses `libbpf` to load the compiled
code, find the parser program code, find the verdict program code, and attach
both to `SOCKHASH` map. After the programs are attached the proxy is ready to be used.

Main implements a simple socket server. It waits for two connections and adds two entries
to the SOCKHASH map. Each entry configures data from one socket to be forwarded to the
other socket.

After the map is populated the main thread can suspend by calling `poll` to wait on
either socket closing. Data between the two sockets is freely forwarded without any
further work on the user process.

## Environment
A Dockerfile is provided to allow development on non-linux environments (like a Mac).

To simplify testing the project deploys to a fly.io free instance.
The Linux Kernels on their hosts come with all the needed eBPF capabilities enabled.

To use, ssh into the deployed instance and use something like nc to start a couple
of connections. Once the second socket is connected data between them should
be forwarded without any explicit work from the user process.
