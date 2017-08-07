#include <stdio.h>
#include <net/ethernet.h> // ETH_ALEN, ETH_P_ARP, ETHERTHYPE_ARP
#include <string.h> // for memcpy
#include <arpa/inet.h> // for htons
#include "arp_request.h"
#include "header.h"
#include "ethernet_address_converter.h"

static void assign_ethernet_header(char *packet, u_char *eth_source) {

	struct ethernet_header *header = (struct ethernet_header*) packet;

	u_char *eth_destination = convert_ethernet_address_to_hexadecimal("FF:FF:FF:FF:FF:FF");

	memcpy(header->destination, eth_destination, ETH_ALEN);
	memcpy(header->source, eth_source, ETH_ALEN);
	header->type = htons(ETHERTYPE_ARP);
}

static void assign_arp_header(char *packet, u_char *eth_source, u_char *ip_source, u_char *ip_destination) {

	struct arp_header *header = (struct arp_header*)(packet + sizeof(struct ethernet_header)); 

	u_char *eth_destination = convert_ethernet_address_to_hexadecimal("00:00:00:00:00:00");

	header->hardware_type = htons(ARPHDR_ETHER);
	header->protocol_type = htons(ETH_P_IP);
	header->hardware_address_length = ETH_ALEN;
	header->protocol_address_length = IP_ALEN;
	header->opcode = htons(ARPOP_REQUEST);
	
	memcpy(header->source_hardware_address, eth_source, ETH_ALEN);
	memcpy(header->source_protocol_address, ip_source, IP_ALEN);

	memcpy(header->destination_hardware_address, eth_destination, ETH_ALEN);
	memcpy(header->destination_protocol_address, ip_destination, IP_ALEN);
}

int get_arp_request_size() {
	return sizeof(struct ethernet_header) + sizeof(struct arp_header);
}

u_char *assign_arp_request(u_char *ethernet_address, u_char *ip_source, u_char *ip_destination) {

	static u_char packet[sizeof(struct ethernet_header) + sizeof(struct arp_header)];

	assign_ethernet_header(packet, ethernet_address);
	assign_arp_header(packet, ethernet_address, ip_source, ip_destination);

	return packet;
}
