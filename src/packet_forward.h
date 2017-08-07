#include <pcap/pcap.h>

void forward(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);