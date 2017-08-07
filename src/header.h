#include <sys/types.h> // for u_char
#include <netinet/tcp.h> // for tcp_seq
#include <net/ethernet.h> // ETH_ALEN, ETH_P_ARP, ETHERTHYPE_ARP

#define IP_ALEN 4
#define ARPHDR_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct spoofing_attack {
	u_char target1_ethernet_address[ETH_ALEN];
	u_char target2_ethernet_address[ETH_ALEN];
	char interface_name[10];
};

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

struct ip_header {
	u_char ip_vhl;
	u_char type_of_service;
	u_short total_length;
	u_short identification;
	u_short offset;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char time_to_live;
	u_char protocol;
	u_short checksum;
	struct in_addr source_address, destination_address;
};
#define IP_HL(ip_header) (((ip_header)->ip_vhl) & 0x0f)
#define IP_V(ip_header) (((ip_header)->ip_vhl) >> 4)

struct tcp_header {
	u_short source_port;
	u_short destination_port;
	tcp_seq sequence_number;
	tcp_seq acknowledgement_number;
	u_char offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short window;
	u_short checksum;
	u_short urgent_pointer;
};

struct udp_header {
	u_short source_port;
	u_short destination_port;
	u_short length;
	u_short checksum;
};
