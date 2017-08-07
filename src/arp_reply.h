#include <sys/types.h> // for u_char
#include <net/ethernet.h> // ETH_ALEN, ETH_P_ARP, ETHERTHYPE_ARP

int get_arp_reply_size();
u_char *spoofed_arp_reply (u_char *own_eth_address, u_char *spoof_ip_address, u_char *target_eth_address, u_char *target_ip_destination);
