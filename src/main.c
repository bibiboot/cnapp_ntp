#include "globals.h"
#include "packet_sniffer.h"

#include <time.h>
#include <sys/time.h>

#define MAX_SEND 10

void *sender(void *val)
{
    int payload_size = 65;
    char payload[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCEDFGHIJKL";
    //char payload[] = "CCCEDFGHIJKLMNOPQRSTUVWXYZABCEDFGHIJKLMNOPQRSTUVWXYZABCEDF00";
    //char payload[] = "ABCEDFGHIJKLMNOPQRSTUVWXYZ";
    //char payload[] = "ABCEDFGHIJKLMNOPQRSTUVWXYZ";
    //char payload[] = "";

    void* packet = (void*)malloc(payload_size + C_HLEN);

    /*Create packet*/
    create_packet(packet, globals.dest_node, DATA_PORT, payload, payload_size);
    int packet_size = payload_size + C_HLEN;

    int i, r;
    struct timespec now;
    for (i=0; i<=MAX_SEND; i++) {
        r = clock_gettime(CLOCK_REALTIME, &now);
        if (r < 0) {
            printf("error with clock_gettime! (%i)\n", r);
            exit(1);
        } else {
            //printf("time is: %s", ctime(&now.tv_sec));
            printf("Send Timestamp :  %lu ns\n", now.tv_sec * SECONDS +
                    now.tv_nsec * NANOSECONDS);
        }
        send_packet_on_line("eth5", packet, packet_size);
    }
}

void start(){
    void *val;
    pthread_create(&globals.sniff_th, 0, sniff, val);
    pthread_create(&globals.sender_th, 0, sender, val);
}

int main(int argc, char *argv[])
{

    if (argc != 3) {
        printf("Two arguments required\n");
        exit(1);
    }

    /**
     * argument 1: Source node
     * argument 2: Destination node
     */
    globals.src_node = atoi(argv[1]);
    globals.dest_node = atoi(argv[2]);

    /* Create file descriptor to write the packet */
    create_log_file();

    globals.send_sock_fd = get_socket();

    start();

    pthread_join(globals.sniff_th, NULL);
    pthread_join(globals.sender_th, NULL);

    return 0;
}
