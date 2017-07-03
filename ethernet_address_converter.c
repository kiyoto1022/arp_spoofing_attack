#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "ethernet_address_converter.h"

static long int convert_str_to_hexadecimal(const char hex_code) {
	if (hex_code >= '0' && hex_code <= '9')
		return (hex_code - '0');
	if (hex_code >= 'A' && hex_code <= 'F')
		return (hex_code - 'A' + 10);
	if (hex_code >= 'a' && hex_code <= 'f')
		return (hex_code - 'a' + 10);
	return -1;
}

static bool is_hex_code(const char hex_code) {
	if (convert_str_to_hexadecimal(hex_code) != -1)
		return true;
	return false;
}

static bool is_shift(int now, int loop_count) {
	if (now + 1 < loop_count)
		return true;
	return false;
}

static int byte_order(long int hexadecimal) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    printf("Byte order is Little endian\n");
    long int little_endian = 0;
    while(1) {
	    little_endian += hexadecimal >> 8 & 0xFF;
	    hexadecimal = hexadecimal >> 8;
	    if (hexadecimal <= 0)
	    	break;
	    little_endian = little_endian << 8;
    }
    return little_endian;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    printf("Byte order is Big endian¥n");
    return hexadecimal;
#endif
}

int convert_ethernet_address_to_hexadecimal(const char *ethernet_address) {
    long int hexadecimal = 0;
    int loop_count = strlen(ethernet_address);
    for(int i=0; i<loop_count; i++) {	

    	if (is_hex_code(ethernet_address[i]) == false)
    		continue; // skip colon

    	hexadecimal += convert_str_to_hexadecimal(ethernet_address[i]);

    	if (is_shift(i, loop_count))
    		hexadecimal = hexadecimal << 4;
    }
    printf("Convert Ethernet address %s to %lx\n", ethernet_address, hexadecimal);
    return byte_order(hexadecimal);
}