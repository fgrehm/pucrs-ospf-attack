#ifndef UTILS_H
#define UTILS_H

#define MAC_ADDR_LEN 6
#define MAX_WAIT_SEC 10
#define PROTO_OSPF 89
#define IPV4_MULTICAST_MAC "01:00:5e:00:00:05"
#define IPV4_MULTICAST_ADDR "224.0.0.5"

#define IPV4_MULTICAST_MAC_2 "01:00:5e:00:00:06"
#define IPV4_MULTICAST_ADDR_2 "224.0.0.6"

int create_socket(char *iface_name);
int send_packet(int sock_fd, unsigned char *dest_mac, unsigned char *buffer, int interface_index, int packet_size);

void die(char *msg);

unsigned char *parse_mac_addr(char *mac_str);

int write_ipv4_ethernet_header(unsigned char *buffer, unsigned char *source_mac, unsigned char *dest_mac);
int write_ipv4_header(unsigned char *buffer, char *source_ip, char *dest_ip, int ip_data_len);

#endif
