#ifndef OSPF_ATTACK_H
#define OSPF_ATTACK_H

#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1500
#define PROTO_OSPF 89
#define IPV4_MULTICAST_MAC "01:00:5e:00:00:05"
#define IPV4_MULTICAST_ADDR "224.0.0.5"

unsigned char *parse_mac_addr(char *mac_str);
int build(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, __u8 packet_type);
int build_database_description_header_ospf(unsigned char buffer[BUFFER_LEN], char *local_ip, unsigned long sequence_number, __u8 control);
int build_hello_header_ospf(unsigned char buffer[BUFFER_LEN], char *local_ip);
int build_lls_data_block(unsigned char buffer[BUFFER_LEN], int pos);

#endif
