#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "checksum.h"
#include "utils.h"
#include "ospf_attack.h"

int create_socket(char *iface_name) {
  int sock_fd;
  // Creates the raw socket to send packets
  if((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    die("Erro na criacao do socket.\n");
  }

  // Set interface to promiscuous mode
  struct ifreq ifr;
  strcpy(ifr.ifr_name, iface_name);
  if(ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
    die("ioctl error!");
  }
  ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
  ifr.ifr_flags |= IFF_PROMISC;
  ioctl(sock_fd, SIOCSIFFLAGS, &ifr);

  struct timeval tv;
  tv.tv_sec = MAX_WAIT_SEC;
  tv.tv_usec = 0;
  setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

  return sock_fd;
}

int send_packet(int sock_fd, unsigned char *dest_mac, unsigned char *buffer, int interface_index, int packet_size) {
  // Identify the machine (MAC) that is going to receive the message sent.
  struct sockaddr_ll dest_addr;
  dest_addr.sll_family = htons(PF_PACKET);
  dest_addr.sll_protocol = htons(ETH_P_ALL);
  dest_addr.sll_halen = 6;
  dest_addr.sll_ifindex = interface_index;
  memcpy(&(dest_addr.sll_addr), dest_mac, MAC_ADDR_LEN);

  // Send the actual packet
  return sendto(sock_fd, buffer, packet_size, 0, (struct sockaddr *)&(dest_addr), sizeof(struct sockaddr_ll));
}

// Based on http://stackoverflow.com/a/3409211
unsigned char *parse_mac_addr(char *mac_str) {
  unsigned char *result = calloc(MAC_ADDR_LEN, sizeof(unsigned char));
  sscanf(mac_str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", result, result + 1, result + 2, result + 3, result + 4, result + 5);

  return result;
}

void die(char *msg) {
  printf("%s\n", msg);
  exit(1);
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
