#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "find_ethernet_address.h"

u_char *find_ethernet_address(char *interface_name) {

	int fd;
	struct ifreq ifr;
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name));
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	static u_char ethernet_address[ETHERNET_ADDRESS_LENGTH];
	
	for (int i=0; i<ETHERNET_ADDRESS_LENGTH; i++) {
		ethernet_address[i] = ifr.ifr_hwaddr.sa_data[i] & 0xff;
	}

	printf("The Ethernet address of the %s is %x:%x:%x:%x:%x:%x\n", interface_name,
			ethernet_address[0], ethernet_address[1], ethernet_address[2],
			ethernet_address[3], ethernet_address[4], ethernet_address[5]);
	return ethernet_address;
}