#pragma once

#include "globals.h"
#include <linux/if_arp.h>

void send_packet_on_line(char *if_name, void *packet,
                         int data_size);
