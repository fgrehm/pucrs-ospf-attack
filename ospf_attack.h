#ifndef OSPF_ATTACK_H
#define OSPF_ATTACK_H

#define MAC_ADDR_LEN 6
#define ETHERTYPE_LEN 2
#define ETHERNET_LEN (2 * MAC_ADDR_LEN + ETHERTYPE_LEN)
#define IP_HEADER_LEN 20
#define IP_ADDR_LEN 4
#define IP_LEN (PACKET_LEN - ETHERNET_LEN)
#define PACKET_LEN 64
#define BUFFER_LEN 1518

#define INTERFACE_INDEX 2
#define INTERFACE_NAME "wlan0"

// #define TTL 64
#define TOTAL_PACKETS 6
#define MAX_WAIT_SEC 2

char *build_hello();

#endif
