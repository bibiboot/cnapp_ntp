#include "packet_send.h"

/**
 * Send packet actually
 * Creates the socket address
 */
void send_packet_on_line(char *if_name, void *packet, int data_size){
    struct ifreq ifr;
    /*target address*/
    struct sockaddr_ll socket_address;

    //Find src interface index
    int src_index = interface_index(globals.send_sock_fd, if_name);

    /*prepare sockaddr_ll*/
    unsigned char dest_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
    create_custom_socket_address(&socket_address, src_index, dest_mac);

    /*send the packet*/
    int send_result = 0;
    send_result = sendto(globals.send_sock_fd, packet,
                         data_size , 0, (struct sockaddr*)&socket_address,
                         sizeof(socket_address));
    if (send_result < 0){
	printf("ERROR: sendto\n");
	perror("sendto");
	exit(1);
    }
}
