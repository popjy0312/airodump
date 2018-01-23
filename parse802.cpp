#include "parse802.h"

int parse(std::map<uint32_t, struct ApData>* ApMap, const unsigned char* packet){
	struct radiotap* 	radioHeader = (struct radiotap*)packet;
	struct beacon*		pbeacon;
	struct ApData*		tmpData;

	DumpHex(packet,32);
	LOG(INFO) << "h_len is "<< radioHeader->h_len;

	if(packet[radioHeader->h_len] == SUBTYPE_DATA_FRAME){
		LOG(INFO) << "SUBTYPE_DATA_FRAME";
	}else if(packet[radioHeader->h_len] == SUBTYPE_PROBE_REQUEST){
		LOG(INFO) << "SUBTYPE_PROBE_REQUEST";
	}else if(packet[radioHeader->h_len] == SUBTYPE_PROBE_RESPONSE){
		LOG(INFO) << "SUBTYPE_PROBE_RESPONSE";
	}else if(packet[radioHeader->h_len] == SUBTYPE_BEACON){
		pbeacon = (struct beacon*)(packet + radioHeader->h_len); 
		if(ApMap->find( hash_bssid(pbeacon->i_addr3)) != ApMap->end()){
			LOG(INFO) << "already";
		}
		else{
			tmpData = (struct ApData*)malloc(sizeof(struct ApData));
			ApMap->insert(std::make_pair(hash_bssid(pbeacon->i_addr3), *tmpData));
			LOG(INFO) << "insert ok";
		}
		LOG(INFO) << "SUBTYPE_BEACON";
		LOG(INFO) << "Addr1 is " << ether_ntoa((struct ether_addr*)&pbeacon->i_addr1);
	}else
		return 0;

	print_data(ApMap);
	return 0;
}

void print_data(std::map<uint32_t, struct ApData>* ApMap){
	printf(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n");
	for(std::map<uint32_t, struct ApData>::iterator it= ApMap->begin(); it != ApMap->end(); it++){
		printf("%X\n", it->first);
	}
}

uint32_t hash_bssid(uint8_t bssid[IEEE80211_ADDR_LEN]){
	uint32_t	res = 0;
	int i;
	for(i=IEEE80211_ADDR_LEN-1; i >= IEEE80211_ADDR_LEN - 4; i--){
		res = res << 8 | bssid[i];
	}
	return res;
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