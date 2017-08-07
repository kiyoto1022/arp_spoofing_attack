#include <pcap/pcap.h>

#define ETHERNET_FRAME_SIZE 1518

pcap_t *init_pcap(char *interface_name);
