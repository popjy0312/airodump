#include "parse802.h"

int parse(const unsigned char* packet){
	struct radiotap* 	radioHeader = (struct radiotap*)packet;
	struct beacon*		pbeacon;

	DumpHex(packet,32);
	printf("h_len is %d\n", radioHeader->h_len);

	if(packet[radioHeader->h_len] == SUBTYPE_DATA_FRAME){
		LOG(INFO) << "data";
	}else if(packet[radioHeader->h_len] == SUBTYPE_PROBE_REQUEST){
		LOG(INFO) << "PROBE_REQUEST";
	}else if(packet[radioHeader->h_len] == SUBTYPE_PROBE_RESPONSE){
		LOG(INFO) << "SUBTYPE_PROBE_RESPONSE";
	}else if(packet[radioHeader->h_len] == SUBTYPE_BEACON){
		pbeacon = (struct beacon*)(packet + radioHeader->h_len); 
		LOG(INFO) << "SUBTYPE_BEACON";
		LOG(INFO) << "Addr1 is " << ether_ntoa((struct ether_addr*)&pbeacon->i_addr1);
	}else
		return 0;

	return 0;
}

// ref: https://gist.github.com/ccbrown/9722406
void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}