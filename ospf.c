#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "ospf.h"
#include "ospf_attack.h"
#include "checksum.h"


//?pedro                                               //verificar se tipo da variável é adequada
int build_link_state_summary_header_ospf(unsigned char buffer[BUFFER_LEN], 
                                    char *local_ip, 
                                    char *dest_ip, 
                                    int size_eth_ip_ospfBasic, 
                                    int tipe_of_service,
                                    unsigned long sequence_number) {

  // OSPF link state summary header
  // possibly necessary a list of this ?pedro
  struct ospf_lss *lss_header_ospf;
  lss_header_ospf = (struct ospf_lss *) &buffer[size_eth_ip_ospfBasic];
  lss_header_ospf->lss_age = LSS_AGE;                                       /* Time (secs) Since Originated ?pedro I can't know if fixed value */
  lss_header_ospf->lss_opts = LSS_OPTIONS;                                  /* Options Supported */
  lss_header_ospf->lss_type = LSST_ROUTE;                                   /* LST_* below ?pedro */
  lss_header_ospf->lss_lsid = inet_addr(local_ip);                          /* Link State Identifier */
  lss_header_ospf->lss_rid = inet_addr(local_ip);                           /* Advertising Router Identifier ?pedro I think would was THE PHANTOM ROUTER*/
  lss_header_ospf->lss_seq = LSS_SEQ_NUM;                                   /* Link State Adv. Sequence #   */
  lss_header_ospf->lss_cksum;  /* ?pedro Fletcher Checksum of LSA */
    // TODO: LENGTH: lss_header_ospf->lss_len;    /* Length of Advertisement ?pedro I don't know, because in wireshark a header has 3 LSS and values not equal*/

  return sizeof(struct ospf_lss);
}

//?pedro                                               //verificar se tipo da variável é adequada
int build_link_state_request_header_ospf(unsigned char buffer[BUFFER_LEN], 
                                    char *local_ip, 
                                    char *dest_ip, 
                                    int size_eth_ip_ospfBasic, 
                                    int tipe_of_service,
                                    unsigned long sequence_number) {

  // OSPF link state request header
  // possibly necessary a list of this ?pedro
  struct ospf_lsr *lsr_header_ospf;
  lsr_header_ospf = (struct ospf_lsr *) &buffer[size_eth_ip_ospfBasic];
  lsr_header_ospf->lsr_type = LSR_TYPE;                                     /* Link State Type      */
  lsr_header_ospf->lsr_lsid = inet_addr(dest_ip);                           /* Link State Identifier "destination ip address" */
  lsr_header_ospf->lsr_rid = inet_addr(dest_ip);                            /* Advertising Router "destination ip address" */

  return sizeof(struct ospf_lsr);
}

//?pedro                                               //verificar se tipo da variável é adequada
int build_database_description_header_ospf(unsigned char buffer[BUFFER_LEN], 
                                    char *local_ip, 
                                    char *dest_ip, 
                                    int size_eth_ip_ospfBasic, 
                                    int tipe_of_service,
                                    unsigned long sequence_number) {

  // OSPF data base description header
  struct ospf_dd *database_description_header_ospf;
  database_description_header_ospf = (struct ospf_dd *) &buffer[size_eth_ip_ospfBasic];
  database_description_header_ospf->dd_mbz = ZERO;                          /* Must Be Zero         */
  database_description_header_ospf->dd_opts = DD_OPTIONS;                   /* Options          */
  // TODO: CONTROL: database_description_header_ospf->dd_control; /* Control Bits (DDC_* below)   */
  database_description_header_ospf->dd_seq = sequence_number;               /* Sequence Number      */
  // TODO: LINK STATE ADVERTISEMENTS LIST: struct ospf_lss dd_lss[1];  /* Link State Advertisements    */
  
  return sizeof(struct ospf_dd);
}


//?pedro                                    //verificar se tipo da variável é adequada
int build_basic_header_ospf(unsigned char buffer[BUFFER_LEN], 
                                    char *local_ip,
                                    char *dest_ip,
                                    //int size_eth_ip,
                                    unsigned char type_of_service) {

  // OSPF header
  struct ospf *basic_header_ospf;
  basic_header_ospf = (struct ospf *) &buffer[sizeof(struct ether_header) + sizeof(struct ip)];
  basic_header_ospf->ospf_version = OSPF_VERSION;                           /* Version Number   */
  basic_header_ospf->ospf_type = 0x01;                           /* Packet Type      */
  basic_header_ospf->ospf_len = htons(sizeof(struct ospf) + sizeof(struct ospf_hello));   /* Packet Length    */
  basic_header_ospf->ospf_rid = inet_addr(local_ip);                        /* Router Identifier    */
  basic_header_ospf->ospf_aid = inet_addr("0.0.0.0");                       /* Area Identifier    */
  // TODO: CHECKSUM:  
  basic_header_ospf->ospf_cksum = 0X0000;                                   /* Check Sum      */
  basic_header_ospf->ospf_authtype = AU_NONE;                               /* Authentication Type    */
  basic_header_ospf->ospf_auth[0] = AUTH_NONE;                              /* Authentication Field */
  //basic_header_ospf->ospf_data[1];    I cut this atribute ?pedro

  return sizeof(struct ospf);
}


//?pedro                                     //verificar se tipo da variável é adequada
int build_hello_header_ospf(unsigned char buffer[BUFFER_LEN], 
                                    char *local_ip, 
                                    char *dest_ip) {

  // OSPF hello header
  struct ospf_hello *hello_header_ospf;
  hello_header_ospf = (struct ospf_hello *) &buffer[sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ospf)];
  hello_header_ospf->oh_netmask = inet_addr("255.255.255.0");               /* Network Mask     */
  hello_header_ospf->oh_hintv = HELLO_INTERVAL;                             /* Hello Interval (seconds) */
  /*OPTIONS DON'T OK*/
  hello_header_ospf->oh_opts = HELLO_OPTIONS;                               /* Options      */
  hello_header_ospf->oh_prio = HELLO_PRIORITY;                              /* Sender's Router Priority */
  hello_header_ospf->oh_rdintv = HELLO_DEAD_INTERVAL;                       /* Seconds Before Declare Dead  */
  hello_header_ospf->oh_drid = inet_addr(local_ip);                         /* Designated Router ID   */
  hello_header_ospf->oh_brid = inet_addr("0.0.0.0");                        /* Backup Designated Router ID  */
  // TODO: NEIGHBOR LIST: hello_header_ospf->oh_neighbor[1];                                        /* Living Neighbors   */
  int swap; 
  swap = build_basic_header_ospf(buffer, local_ip, dest_ip, 0X01); /* size_eth_ip, */ 
  
  return sizeof(struct ospf_hello) + swap;
}
