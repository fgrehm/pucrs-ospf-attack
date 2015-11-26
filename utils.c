#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "checksum.h"
#include "utils.h"
#include "ospf_attack.h"

// Based on http://stackoverflow.com/a/3409211
unsigned char *parse_mac_addr(char *mac_str) {
  unsigned char *result = calloc(MAC_ADDR_LEN, sizeof(unsigned char));
  sscanf(mac_str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", result, result + 1, result + 2, result + 3, result + 4, result + 5);

  return result;
}

int write_ipv4_ethernet_header(unsigned char *buffer, unsigned char *source_mac, unsigned char *dest_mac) {
  struct ether_header *eth_header = (struct ether_header *) buffer;
  memcpy(eth_header->ether_shost, source_mac, MAC_ADDR_LEN);
  memcpy(eth_header->ether_dhost, dest_mac, MAC_ADDR_LEN);
  eth_header->ether_type = htons(0x800);
  return sizeof(struct ether_header);
}

int write_ipv4_header(unsigned char *buffer, char *source_ip, char *dest_ip, int ip_data_len) {
  struct ip *ip_header = (struct ip *) buffer;
  ip_header->ip_hl = 0x05; // 20 bytes
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0xc0;
  ip_header->ip_len = htons(ip_data_len + sizeof(struct ip));
  ip_header->ip_id = 0;
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 1;
  ip_header->ip_p = PROTO_OSPF;
  ip_header->ip_sum = 0x0000;
  ip_header->ip_src.s_addr = inet_addr(source_ip);
  ip_header->ip_dst.s_addr = inet_addr(dest_ip);
  ip_header->ip_sum = in_cksum((unsigned short*)ip_header, sizeof(struct ip));
  return sizeof(struct ip);
}
