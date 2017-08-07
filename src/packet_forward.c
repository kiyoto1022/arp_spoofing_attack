#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include "header.h"
#include "packet_forward.h"

int tcp_packet_count = 0;
int udp_packet_count = 0;

void forward(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct spoofing_attack *spoofing_attack = (struct spoofing_attack*) args;

	// for debug
	printf("args -> target1_ethernet_address [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		spoofing_attack->target1_ethernet_address[0], spoofing_attack->target1_ethernet_address[1], spoofing_attack->target1_ethernet_address[2],
		spoofing_attack->target1_ethernet_address[3], spoofing_attack->target1_ethernet_address[4], spoofing_attack->target1_ethernet_address[5]);

	printf("args -> target2_ethernet_address [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		spoofing_attack->target2_ethernet_address[0], spoofing_attack->target2_ethernet_address[1], spoofing_attack->target2_ethernet_address[2],
		spoofing_attack->target2_ethernet_address[3], spoofing_attack->target2_ethernet_address[4], spoofing_attack->target2_ethernet_address[5]);	
	
	printf("args -> interface_name [%s]\n", spoofing_attack->interface_name);

	struct ethernet_header *eth_header = (struct ethernet_header*)packet;
	struct ip_header *ip_hdr = (struct ip_header*)(packet + 14);

	if(ip_hdr->protocol == IPPROTO_TCP) {
		tcp_packet_count += 1;
	}

	if(ip_hdr->protocol == IPPROTO_UDP) {
		udp_packet_count += 1;
	}

	printf("\rTCP: %d Packet , UDP: %d Packet", tcp_packet_count, udp_packet_count);
}
