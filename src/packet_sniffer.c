#include "packet_sniffer.h"
#include <net/if.h>

#define PACKET_LEN 65536

#define EXTRACT_64BITS(p) \
        ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 0) << 56 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 1) << 48 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 2) << 40 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 3) << 32 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 4) << 24 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 5) << 16 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 6) << 8 | \
                         (u_int64_t)*((const u_int8_t *)(p) + 7)))

void print_timestamp_hex(unsigned char *timestamp_payload)
{
    printf("Timestamp payload : ");
    int i;
    for(i=0; i<8; i++) {
        printf(" %.2X", timestamp_payload[i]);
    }
    printf("\n");
}

void print_timestamp_payload(unsigned char *payload, int payload_size, int fixed_size)
{
    unsigned char *timestamp_payload = payload + fixed_size;
    int timestamp_payload_size = payload_size - fixed_size;

    print_timestamp_hex(timestamp_payload);
    int i;
    for(i=0; i<4; i++) {
        char temp = timestamp_payload[i];
        timestamp_payload[i] = timestamp_payload[7-i];
        timestamp_payload[7-i] = temp;
    }
    print_timestamp_hex(timestamp_payload);

    printf("Timestamp payload :  %lu\n",EXTRACT_64BITS(timestamp_payload));
}

void print_human_read_payload(unsigned char *packet, int packet_size)
{
    printf(KCYN "SNIFF:++++++++++++++++++++++++++++++++\n" RESET);
    struct custom_ethernet *eth_header = (struct custom_ethernet*)packet;
    struct custom_ip *ip_header = (struct custom_ip*)( packet + C_ETHLEN );
    struct custom_udp *udp_header = (struct custom_udp*)( packet + C_ETHLEN + C_IPLEN );
    unsigned char *payload = packet + C_HLEN;

    int fixed_size = 65;
    int payload_size = payload_size - C_HLEN;
    print_timestamp_payload(payload, payload_size, fixed_size);

    print_timestamp_payload(payload, payload_size, 65 + 8);

    printf("Total [%d]: Header size [%d]: Payload [%d]: %s\n",
            packet_size, C_HLEN,packet_size - C_HLEN, payload);
    printf("++++++++++++++++++++++++++++++++++++++++++++\n");
    /*
    printf("| %s ",
            print_human_format_number(ntohs(eth_header->dest_mac), "ETHERNET"));
    printf("| %s ",
            print_human_format_number(ntohs(ip_header->src_ip), "IP"));
    printf("| %s ",
           print_human_format_number(ntohs(ip_header->dest_ip), "IP"));
    printf("| %s |",
            print_human_format_number(ntohs(udp_header->port), "UDP"));
    printf("\n++++++++++++++++++++++++++++++++++++++++++++\n");

    get_pattern(packet);
    */
}

int process_custom_packet(unsigned char* buffer, int size)
{
    print_data_detail(buffer, size);
    print_human_read_payload(buffer, size);
    fflush(LOGFILE);
    return 1;
}

int set_promisc(char *interface, int sock ) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface,strlen(interface)+1);
    if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)) {
        /*Could not retrieve flags for the
        * interface*/
        perror("Could not retrive flags for the interface");
        exit(0);
    }
    //printf("DEBUG: The interface is ::: %s\n", interface);
    //perror("DEBUG: Retrieved flags from interface successfully");

    /*now that the flags have been
    * retrieved*/
    /* set the flags to PROMISC */
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1 ) {
        perror("Could not set the PROMISC flag:");
        exit(0);
    }
    //printf("DEBUG: Setting interface ::: %s ::: to promisc\n", interface);
    return(0);
}


void* sniff(void *val)
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *) malloc(PACKET_LEN);
    memset(buffer, '\0', PACKET_LEN);

    printf("Starting...\n");

    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    if (sock_raw < 0) {
        perror("Socket Error");
        return;
    }

    /**
     * Set it on promiscous mode,
     * Otherwise it won't sniff packet
     * Which do not belong to him
     */
    set_promisc(INF0, sock_raw);

    struct timespec now;
    int r;

    while(1) {
        saddr_size = sizeof saddr;
        // Receive a packet
        data_size = recvfrom(sock_raw , buffer , PACKET_LEN , 0 , &saddr , (socklen_t*)&saddr_size);

        r = clock_gettime(CLOCK_REALTIME, &now);
        if(data_size <0 )
        {
            printf("Error: Recvfrom error , failed to get packets\n");
            return ;
        }

        if ( !is_allowed(buffer) ) {
            continue;
        }
        if (r < 0) {
            printf("error with clock_gettime! (%i)\n", r);
            exit(1);
        } else {
            printf("time is: %s", ctime(&now.tv_sec));
            printf("time as int is: %lu ns\n", now.tv_sec * SECONDS +
                    now.tv_nsec * NANOSECONDS);
        }

        printf("Data size = %d\n", data_size);

        /* Track count of the packet type */
        process_custom_packet(buffer , data_size);

        //incoming_packet_handler(buffer, data_size);

        memset(buffer, '\0', PACKET_LEN);

        fflush(LOGFILE);
        fflush(stdout);
    }

    close(sock_raw);
}
