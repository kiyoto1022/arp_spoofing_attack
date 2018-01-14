#include <stdio.h>
#include <pcap/pcap.h> // for pcap_pkthdr
#include <netinet/ip.h> // for IPPROTO_TCP IPPROTO_UDP
#include <string.h> // for memcmp
#include <stdlib.h> // for exit
#include <errno.h> // for errno strerror
#include <unistd.h> // for usleep
#include "header.h"
#include "packet_forward.h"

int tcp_packet = 0;
int udp_packet = 0;
int other_packet = 0;

static int get_packet_size(const u_char *packet) {
	struct ip_header *ip_hdr = (struct ip_header*)(packet + 14);
	return ntohs(ip_hdr->total_length);
}

static void overwrite_ethernet_address(u_char *forgery_packet, struct forward_struct *forward_struct) {

	struct ethernet_header *eth_header = (struct ethernet_header*)forgery_packet;
	
	if (memcmp(forward_struct->target1_ethernet_address, eth_header->source, ETH_ALEN) == 0) {
		memcpy(eth_header->source, forward_struct->attackers_ethernet_address, ETH_ALEN);
		memcpy(eth_header->destination, forward_struct->target2_ethernet_address, ETH_ALEN);
	}

	if (memcmp(forward_struct->target2_ethernet_address, eth_header->source, ETH_ALEN) == 0) {
		memcpy(eth_header->source, forward_struct->attackers_ethernet_address, ETH_ALEN);
		memcpy(eth_header->destination, forward_struct->target1_ethernet_address, ETH_ALEN);
	}
}

static void forwarding(u_char *forgery_packet, struct forward_struct *forward_struct) {
	
	struct sockaddr sockaddr;
	strncpy(sockaddr.sa_data, forward_struct->interface_name, sizeof(sockaddr.sa_data));

	if(sendto(forward_struct->send_socket, forgery_packet, get_packet_size(forgery_packet), 0, &sockaddr, sizeof(sockaddr)) < 0) {
		printf("\nFailed to send forwarding : %s\n", strerror(errno));
		return;
	}
}

static void countup(const u_char *packet) {

	struct ip_header *ip_hdr = (struct ip_header*)(packet + 14);
	switch(ip_hdr->protocol) {
		case IPPROTO_TCP: tcp_packet += 1; break;
		case IPPROTO_UDP: udp_packet += 1; break;
		default: other_packet += 1; break;
	}
	printf("\rTCP: %d Packet , UDP: %d Packet , OTHER: %d Packet", tcp_packet, udp_packet, other_packet);
}

void forward_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct forward_struct *forward_struct = (struct forward_struct*)args;	

	countup(packet);

	u_char forgery_packet[get_packet_size(packet)];
	memcpy(forgery_packet, packet, get_packet_size(packet));

	overwrite_ethernet_address(forgery_packet, forward_struct);

	forwarding(forgery_packet, forward_struct);

	// To avoid No buffer space available Error.
	usleep(100);
}
