#pragma once
#include <linux/bpf.h>
struct socket_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u32 src_port;
  __u32 dst_port;
};
