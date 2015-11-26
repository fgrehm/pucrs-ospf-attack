#ifndef OSPF_ATTACK_H
#define OSPF_ATTACK_H

#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1500

#define PROTO_OSPF 89

unsigned char *parse_mac_addr(char *mac_str);
int build_hello(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, unsigned char *dest_mac, char *dest_ip);

#endif
