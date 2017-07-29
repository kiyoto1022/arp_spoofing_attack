#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "pcap_init.h"

static void pcap_lookup(char * interface_name, bpf_u_int32 *network_address, bpf_u_int32 *subnet_mask) {

	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_lookupnet(interface_name, network_address, subnet_mask, errbuf) == -1) {
		printf("Couldn't get netmask for device %s: %s\n", interface_name, errbuf);
		*network_address = 0;
		*subnet_mask = 0;
	}
}

static pcap_t *open_capture_device(char *interface_name) {

	static pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(interface_name, ETHERNET_FRAME_SIZE, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("Couldn't open device %s: %s\n", interface_name, errbuf);
		exit(1);
	}
	return handle;
}

static void is_link_layer_ethernet(pcap_t *handle, char *interface_name) {

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("%s is not an Ethernet\n", interface_name);
		exit(1);
	}
}

static void compile_the_filter(pcap_t *handle, bpf_u_int32 network_address) {

	char filter_exp[] = "ip";
	struct bpf_program fp;

	if (pcap_compile(handle, &fp, filter_exp, 0, network_address) == -1) {
		printf("Can't compile pcap filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Coundn't install filter %s:%s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	pcap_freecode(&fp);
}

pcap_t *init_pcap(char *interface_name) {

	static pcap_t *handle;

	bpf_u_int32 network_address;
	bpf_u_int32 subnet_mask;

	pcap_lookup(interface_name, &network_address, &subnet_mask);

	handle = open_capture_device(interface_name);

	is_link_layer_ethernet(handle, interface_name);
	compile_the_filter(handle, network_address);

	return handle;
}
