#ifndef OSPF_ATTACK_H
#define OSPF_ATTACK_H

#define BUFFER_LEN 1500
#define PROTO_OSPF 89
#define IPV4_MULTICAST_MAC "01:00:5e:00:00:05"
#define IPV4_MULTICAST_ADDR "224.0.0.5"
#define ROUTER_MAC "50:3d:e5:d9:07:b8"

int attack_write_hello(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, char *router_ip);
int attack_write_db_description(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, char *router_ip, __u32 sequence_number, __u8 control);
int attack_write_ls_update(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, char *router_ip);

#endif
