#include <sys/types.h> // for u_char
#include <net/ethernet.h> // ETH_ALEN, ETH_P_ARP, ETHERTHYPE_ARP

#define IP_ALEN 4
#define ARPHDR_ETHER 1
#define ARPOP_REQUEST 1

struct ethernet_header {
	u_char  destination[ETH_ALEN];
	u_char  source[ETH_ALEN];
	u_short type;
};

struct arp_header {
	u_short hardware_type;
	u_short protocol_type;
	char hardware_address_length;
	char protocol_address_length;
	u_short opcode;
	u_char source_hardware_address[ETH_ALEN];
	u_char source_protocol_address[IP_ALEN];
	u_char destination_hardware_address[ETH_ALEN];
	u_char destination_protocol_address[IP_ALEN];
};

int get_arp_request_size();
u_char *assign_arp_request(u_char *ethernet_address, u_char *ip_source, u_char *ip_destination);