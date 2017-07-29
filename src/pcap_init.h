#include <pcap/pcap.h>

#define ETHERNET_FRAME_SIZE 1518
#define PROMISCUOUS_MODE_ON 1
#define TIME_OUT 1000
#define OPTIMISATION_OFF 0

pcap_t *init_pcap(char *interface_name);
