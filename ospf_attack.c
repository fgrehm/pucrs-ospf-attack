#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "ospf_attack.h"

int build_hello(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, unsigned char *dest_mac, char *dest_ip) {
  // Ethernet header
  struct ether_header *eth_header;
  eth_header = (struct ether_header *) &buffer[0];
  memcpy(eth_header->ether_dhost, dest_mac, MAC_ADDR_LEN);
  memcpy(eth_header->ether_shost, local_mac, MAC_ADDR_LEN);
  eth_header->ether_type = htons(0X800);

  struct ip *ip_header;
  ip_header = (struct ip *) &buffer[sizeof(struct ether_header)];
  ip_header->ip_hl = sizeof(struct ip) >> 2;
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0;
  ip_header->ip_len = sizeof(struct ip);
  ip_header->ip_id = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 64;
  // TODO: PROTOCOLO: ip_header->ip_p = IPPROTO_TCP;
  // TODO: CHECKSUM:  ip_header->ip_sum
  ip_header->ip_src.s_addr = inet_addr(local_ip);
  ip_header->ip_dst.s_addr = inet_addr(dest_ip);

  return sizeof(struct ether_header) + sizeof(struct ip);
}
