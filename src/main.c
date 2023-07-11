#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "socket_key.h"


int print_fn(enum libbpf_print_level level, const char *buf, va_list ap) {
  printf("%d:", level);
  return printf(buf, ap);
}

struct bpf_object* open_bpf(const char * file) {
  struct bpf_object_open_opts const opts = {
      .sz = sizeof(struct bpf_object_open_opts),
      .kernel_log_level = 5,
  };
  return bpf_object__open_file(file, &opts);
}

void print_program_info(struct bpf_object const * obj) {
  struct bpf_program *prog;
  bpf_object__for_each_program(prog, obj) {
    printf("name:%s\n", bpf_program__name(prog));
    printf("section_name:%s\n", bpf_program__section_name(prog));
    printf("autoload:%d\n", bpf_program__autoload(prog));
    printf("autoattach:%d\n", bpf_program__autoattach(prog));
    printf("insn_cnt:%zu\n", bpf_program__insn_cnt(prog));
    printf("fd:%d\n", bpf_program__fd(prog));
    printf("attach_type::%s\n",
           libbpf_bpf_attach_type_str(bpf_program__expected_attach_type(prog)));
    printf("\n");
  }
}

void print_map_info(struct bpf_map const *map) {
  printf("name:%s\n", bpf_map__name(map));
  printf("map_type:%s\n", libbpf_bpf_map_type_str(bpf_map__type(map)));
  printf("autocreate:%d\n", bpf_map__autocreate(map));
  printf("max_entries:%u\n", bpf_map__max_entries(map));
  printf("key_size:%u\n", bpf_map__key_size(map));
  printf("value_size:%u\n", bpf_map__value_size(map));
  printf("fd:%d\n", bpf_map__fd(map));
  printf("\n");
}

void print_bpf_error(const char * msg) {
    char buf[10000];
    libbpf_strerror(errno, buf, sizeof(buf));
    printf("%s:\n%s\n", msg, buf);
}

int create_listen_socket(unsigned int ip, unsigned int port) {
  struct sockaddr_in soaddr = {.sin_family = AF_INET, .sin_addr = ip, .sin_port = htons(port)};
  int sock = socket(soaddr.sin_family, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    perror("creating socket");
    return -1;
  }
  int one = 1;
  struct {
    int l_onoff;
    int l_linger;
  } linger = {.l_onoff = 1, .l_linger = 5};
  if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0) {
    perror("setting linger");
    return -1;
  }
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
    perror("setting reuseaddr");
    return -1;
  }
  if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
    perror("setting nodelay");
    return -1;
  }
  if (bind(sock, (const struct sockaddr *)&soaddr, sizeof(soaddr)) != 0) {
    perror("binding");
    return -1;
  }
  if (listen(sock, 5) != 0) {
    perror("listening");
    return -1;
  }
  return sock;
}
int main(void) {
  int rval = 0;
  libbpf_set_print(print_fn);
  struct bpf_object *obj = open_bpf("bpf.elf");
  print_program_info(obj);

  if (bpf_object__load(obj) < 0) {
    print_bpf_error("error loading elf file");
    rval = -1;
    goto end;
  }
  const struct bpf_program *parser =
      bpf_object__find_program_by_name(obj, "bpf_prog_parser");
  const struct bpf_program *verdict =
      bpf_object__find_program_by_name(obj, "bpf_prog_verdict");
  struct bpf_map *map = bpf_object__next_map(obj, NULL);

  int err = bpf_prog_attach(bpf_program__fd(parser), bpf_map__fd(map),
                            BPF_SK_SKB_STREAM_PARSER, 0);
  if (err) {
    print_bpf_error("failed to attach parser to map");
    rval = -1;
    goto end;
  }

  err = bpf_prog_attach(bpf_program__fd(verdict), bpf_map__fd(map),
                        BPF_SK_SKB_STREAM_VERDICT, 0);
  if (err) {
    print_bpf_error("failed to attach verdict to map");
    rval = -1;
    goto end;
  }

  int port = 2234;
  int local_ip;
  inet_pton(AF_INET, "127.0.0.1", &local_ip);
 int sock = create_listen_socket(local_ip, port);
  printf("Listening on port %d\n", port);

#define nclients 2
  struct sockaddr_in clients[nclients] = {};
  int soclients[nclients] = {};
  socklen_t addrlen = sizeof(clients[0]);
  for (size_t i = 0; i < nclients; i++) {
    soclients[i] = accept(sock, (struct sockaddr *)&(clients[i]), &addrlen);
    if (soclients[i] < 0) {
      perror("accepting");
      rval = -1;
      goto close_clients;
    }
    char buff[1000] = {};
    inet_ntop(clients[i].sin_family, &clients[i], (char *)&buff, sizeof(buff));
    printf("Accepted from %s:%d\n", buff, clients[i].sin_port);
  }

  // unsigned int key = 0;
  struct socket_key key = {
      .src_ip = local_ip,
      .dst_ip = clients[0].sin_addr.s_addr,
      .src_port = clients[0].sin_port,
      .dst_port = port,
  };
  struct socket_key key2 = {
      .src_ip = local_ip,
      .dst_ip = clients[1].sin_addr.s_addr,
      .src_port = clients[1].sin_port,
      .dst_port = port,
  };
  printf("key: s_ip=%d, d_ip=%d\n", key.src_ip, key.dst_ip);
  printf("key: s_port=%d, d_port=%d\n", key.src_port, key.dst_port);
  printf("key2: s_ip=%d, d_ip=%d\n", key2.src_ip, key2.dst_ip);
  printf("key2: s_port=%d, d_port=%d\n", key2.src_port, key2.dst_port);

  printf("port: %d, htons(port):%d\n", port, htons(port));
  if (bpf_map__update_elem(map, &key, sizeof(key), &(soclients[1]), sizeof(int),
                           BPF_ANY) < 0) {
    print_bpf_error("error updating map with 1st key");
    rval = -1;
    goto end;
  }
  if (bpf_map__update_elem(map, &key2, sizeof(key), &(soclients[0]),
                           sizeof(int), BPF_ANY) < 0) {
    print_bpf_error("error updating map with 2nd key");
    rval = -1;
    goto end;
  }

  printf("waiting for close\n");
  struct pollfd fds[2] = {
      {.fd = soclients[0], .events = POLLRDHUP},
      {.fd = soclients[1], .events = POLLRDHUP},
  };

  poll(fds, sizeof(fds) / sizeof(fds[0]), -1);

close_clients:
  for (size_t i = 0; i < nclients; i++) {
    close(soclients[i]);
  }
close:
  close(sock);

end:
  bpf_object__close(obj);
  return rval;
}
