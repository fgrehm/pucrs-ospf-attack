#ifndef OSPF_ATTACK_H
#define OSPF_ATTACK_H

#define BUFFER_LEN 1500

struct attack_env {
  int sock_fd;
  unsigned char buffer[BUFFER_LEN];

  char *iface_name;
  int iface_index;

  unsigned char *router_mac;
  char *router_ip;

  unsigned char *local_mac;
  char *local_ip;
};

void attack_establish_adjacency(struct attack_env *env);

#endif
