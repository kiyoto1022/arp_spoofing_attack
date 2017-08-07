#include <sys/types.h> // for u_char
#include <net/ethernet.h> // ETH_ALEN, ETH_P_ARP, ETHERTHYPE_ARP

int get_arp_request_size();
u_char *assign_arp_request(u_char *ethernet_address, u_char *ip_source, u_char *ip_destination);
