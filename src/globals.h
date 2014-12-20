#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <linux/if_ether.h>
#include<netinet/ip.h>    //Provides declarations for ip header
#include <pthread.h>

#include "config.h"
#include "cprotocol.h"
#include "color.h"

#define PACKET_SIZE 65536
// Print function name, filename and line number in print
#define DBG(...) do{fprintf(stderr, "%s (%s, line %d): ", __func__, __FILE__, __LINE__); \
                         fprintf(stderr, __VA_ARGS__);           \
                         fprintf(stderr, "\n");} while(0)

#define SECONDS      1000000000
#define MILLISECONDS 1000000
#define MICROSECONDS 1000
#define NANOSECONDS  1

#define INF0 "eth5"

#define MULTICAST_IP "224.0.0.9"

#define EXTRACT_16BITS(p) \
	((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 0) << 8 | \
		     (u_int16_t)*((const u_int8_t *)(p) + 1)))

#define EXTRACT_32BITS(p) \
	((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 0) << 24 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 1) << 16 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 2) << 8 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 3)))


FILE *LOGFILE;

struct globals {
    int send_sock_fd;
    uint16_t src_node, dest_node;
    pthread_t sniff_th, sender_th;
    struct config config;
};

extern struct globals globals;
