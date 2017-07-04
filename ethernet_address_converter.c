#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
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

static int get_hexadecimal(const char previous_4_bits, char after_4_bits) {
	return convert_str_to_hexadecimal(previous_4_bits) * 16 + convert_str_to_hexadecimal(after_4_bits); 
}

static u_char *byte_order(const u_char *hexadecimal) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	static u_char little_endian[ETHERNET_ADDRESS_LENGTH];
	int i, j;
	for (i=5, j=0; i>=0; i--, j++) {
		little_endian[j] = hexadecimal[i];
	}

	printf("Byte order is Little endian [%x:%x:%x:%x:%x:%x] \n",
			ittle_endian[0], little_endian[1], little_endian[2],
			little_endian[3], little_endian[4], little_endian[5]);

	return little_endian;

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	printf("Byte order is Big endian [%x:%x:%x:%x:%x:%x] \n",
			hexadecimal[0], hexadecimal[1], hexadecimal[2],
			hexadecimal[3], hexadecimal[4], hexadecimal[5]);

	return hexadecimal;

#endif
}

u_char *convert_ethernet_address_to_hexadecimal(const char *ethernet_address) {
	u_char hexadecimal[ETHERNET_ADDRESS_LENGTH];
	for(int i=0; i<ETHERNET_ADDRESS_LENGTH; i++) {
		hexadecimal[i] = (u_char)get_hexadecimal(ethernet_address[i*3], ethernet_address[i*3+1]); 
	}

	printf("Convert to %x:%x:%x:%x:%x:%x\n",
			hexadecimal[0], hexadecimal[1], hexadecimal[2],
			hexadecimal[3], hexadecimal[4], hexadecimal[5]);

	return byte_order(hexadecimal);
}