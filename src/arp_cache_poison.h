#include <sys/types.h> // for u_char

void arp_cache_poison(char *interface_name,
	u_char *target1_ethernet_address, u_char *target1_ip_address,
	u_char *target2_ethernet_address, u_char *target2_ip_address);
