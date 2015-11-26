#ifndef UTILS_H
#define UTILS_H

#define MAC_ADDR_LEN 6

unsigned char *parse_mac_addr(char *mac_str);
int write_ipv4_ethernet_header(unsigned char *buffer, unsigned char *source_mac, unsigned char *dest_mac);
int write_ipv4_header(unsigned char *buffer, char *source_ip, char *dest_ip, int ip_data_len);

#endif
