struct ethernet_header {
	u_char  destination[ETH_ALEN];
	u_char  source[ETH_ALEN];
	u_short type;
};

struct arp_header
{
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

void assign_arp_request(u_char *packet, char *interface_name, u_char *ip_destination);