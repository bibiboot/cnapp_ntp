#include<netinet/ip.h>    //declarations for ip header
#include <linux/if_ether.h>
#include<netinet/ip_icmp.h>   //declarations for icmp header

#include "globals.h"
#include "print_packet.h"
#include "util.h"

bool is_allowed(unsigned char *packet);
