#ifndef OSPF_ATTACK_H
#define OSPF_ATTACK_H

#define ETHERTYPE_LEN 2
#define IP_ADDR_LEN 4
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518

#define PROTO_OSPF 89

int build_hello(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, unsigned char *dest_mac, char *dest_ip);

#endif
