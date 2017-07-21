#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h> // for htons, inet_addr
#include "find_target_ethernet_address.h"

int main(int argc, char**argv) {

	unsigned long own_ip_address = inet_addr("192.168.64.1");
	unsigned long target_ip_address = inet_addr("192.168.64.2");

	u_char *target_ethernet_address = 
		get_target_ethernet_address("enp0s5", (u_char*)&own_ip_address, (u_char*)&target_ip_address);

	printf("Target ethernet address [%x:%x:%x:%x:%x:%x]\n",
		target_ethernet_address[0], target_ethernet_address[1], target_ethernet_address[2],
		target_ethernet_address[3], target_ethernet_address[4], target_ethernet_address[5]);
	return 0;
}
