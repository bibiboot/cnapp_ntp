#pragma once

#include "globals.h"

#define ROUTER_MAC 0
#define NODE1_MAC 1
#define NODE2_MAC 2
#define NODE3_MAC 3

#define NODE1_IP 1
#define NODE2_IP 2
#define NODE3_IP 3

#define DATA_PORT 0
#define NACK_PORT 1

#define C_ETHLEN sizeof(struct custom_ethernet)
#define C_IPLEN sizeof(struct custom_ip)
#define C_UDPLEN sizeof(struct custom_udp)
//#define C_HLEN C_ETHLEN + C_IPLEN + C_UDPLEN
#define C_HLEN 8


struct data {
    uint32_t dest_mac;
    uint32_t src_mac;
};

struct pattern {
    uint64_t value;
};

struct custom_ethernet {
    uint16_t dest_mac;
};

struct custom_ip {
    uint16_t src_ip;
    uint16_t dest_ip;
};

struct custom_udp {
    uint16_t port;
};
