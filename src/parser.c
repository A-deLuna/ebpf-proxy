#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "socket_key.h"

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(max_entries, 2);
  __type(key, struct socket_key);
  __type(value, __u32);
} sock_hash_rx SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
  bpf_printk("parser\n");
  bpf_printk("skb length: %d\n", skb->len);
  return skb->len;
}

static inline void extract_socket_key(struct __sk_buff *skb,
                                      struct socket_key *key) {
  key->src_ip = skb->remote_ip4;
  key->dst_ip = skb->local_ip4;
  key->src_port = skb->remote_port >> 16;
  key->dst_port = skb->local_port;
  bpf_printk("key: s_ip=%d, dst_ip=%d\n", skb->remote_ip4, skb->local_ip4);
  bpf_printk("key: s_port=%d d_port=%d\n",skb->remote_port >> 16,  skb->local_port);
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
  bpf_printk("verdict\n");
  struct socket_key key;

  extract_socket_key(skb, &key);

  return bpf_sk_redirect_hash(skb, &sock_hash_rx, &key, 0);
}

char _license[] SEC("license") = "GPL";
