#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h> // for htons, inet_addr
#include <stdlib.h> // for exit
#include <string.h>
#include "find_ethernet_address.h"
#include "arp_request.h"
#include "find_target_ethernet_address.h"

static void send_arp_request(char *interface_name, u_char *my_ip_address, u_char *target_ip_address) {
	
	u_char *ethernt_address = find_ethernet_address(interface_name);

	u_char *arp_request_packet = assign_arp_request(ethernt_address, target_ip_address, my_ip_address);

	int send_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if(send_socket < 0) {
		printf("Failed to create send socket for arprequest.\n");
		exit(1);
	}

	struct sockaddr sockaddr;
	strncpy(sockaddr.sa_data, interface_name, sizeof(sockaddr.sa_data));
	if(sendto(send_socket, arp_request_packet, get_arp_request_size(), 0, &sockaddr, sizeof(sockaddr)) < 0) {
		printf("Failed to send arprequest.\n");
		exit(1);
	}
}

static u_char *get_sender_ethernet_address(char *reply_packet) {

	struct ethernet_header *ethernet_header = (struct ethernet_header*)reply_packet;
	struct arp_header *arp_header = (struct arp_header*)(reply_packet + sizeof(struct ethernet_header));
	
	if((ethernet_header->type != 1544) || (arp_header->opcode != 512)) {
		printf("Failure because it is not arpreqly.\n");
		exit(1);
	}

	printf("Sender ethernet address of arpreply [%x:%x:%x:%x:%x:%x]\n",
		ethernet_header->source[0], ethernet_header->source[1], ethernet_header->source[2],
		ethernet_header->source[3], ethernet_header->source[4], ethernet_header->source[5]);
	return ethernet_header->source;
}

static u_char *receive_arp_reply() {

	int read_socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
	if(read_socket < 0) {
		printf("Failed to create read socket for arpreply.\n");
		exit(1);
	}
	
	static u_char reply_packet[sizeof(struct ethernet_header) + sizeof(struct arp_header)];
	read(read_socket, reply_packet, get_arp_request_size());

	return reply_packet;
}

u_char *get_target_ethernet_address(char *interface_name, u_char *my_ip_address, u_char *target_ip_address) {

	send_arp_request(interface_name, my_ip_address, target_ip_address);

	u_char *reply_packet = receive_arp_reply(); // TODO: Change to polling
	return get_sender_ethernet_address(reply_packet);
}
