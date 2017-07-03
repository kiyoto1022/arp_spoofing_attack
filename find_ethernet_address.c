#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "find_ethernet_address.h"

void find_ethernet_address(const char *interface_name, u_char *ethernet_address) {

	const char *ETHERNET_ADDRESS_FORMAT = "%02x:%02x:%02x:%02x:%02x:%02x"; 

	int fd;
	struct ifreq ifr;
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface_name, sizeof(interface_name));
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	
	sprintf(ethernet_address, ETHERNET_ADDRESS_FORMAT,
			ifr.ifr_hwaddr.sa_data[0] & 0xff,
			ifr.ifr_hwaddr.sa_data[1] & 0xff,
			ifr.ifr_hwaddr.sa_data[2] & 0xff,
			ifr.ifr_hwaddr.sa_data[3] & 0xff,
			ifr.ifr_hwaddr.sa_data[4] & 0xff,
			ifr.ifr_hwaddr.sa_data[5] & 0xff);
	
	printf("The Ethernet address of the %s is %s\n", interface_name, ethernet_address);
}