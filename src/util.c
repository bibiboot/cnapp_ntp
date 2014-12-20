#include "util.h"
#include "print_packet.h"

void set_pattern(unsigned char *packet, uint64_t pttn_num)
{
    struct pattern *pttn = (struct pattern*)packet;
    pttn->value = htobe64(pttn_num);
}

uint64_t get_pattern(unsigned char *packet)
{
    struct pattern *pttn = (struct pattern*)packet;
    //printf("Pattern = %" PRId64 "\n", be64toh(pttn->value));
    return be64toh(pttn->value);
}

void create_log_file(){
    LOGFILE = fopen("log.txt","w");
    if (LOGFILE == NULL)
    {
        printf("Unable to create log.txt file.");
    }
}
