#include <linux/if_ether.h>
#include "globals.h"

char* print_human_format_number(uint16_t num, char *type);
void print_routed_packet(struct sockaddr_in dest, char *result_if_name, char *src_mac, char *dest_mac);

void print_data_detail (unsigned char* data , int size);
