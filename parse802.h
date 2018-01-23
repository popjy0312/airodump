#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <glog/logging.h>
#include <netinet/ether.h>
#include <map>

#define SUBTYPE_DATA_FRAME 		0x20
#define SUBTYPE_PROBE_REQUEST 	0x40
#define SUBTYPE_PROBE_RESPONSE 	0x50
#define SUBTYPE_BEACON 			0x80

#define IEEE80211_ADDR_LEN 		6

struct radiotap{
    uint8_t 	h_revision;
    uint8_t 	h_pad;
    uint16_t 	h_len;
    uint32_t 	pre_flag;
}__attribute__((__packed__));

struct beacon{
	uint8_t	i_fc[2];
	uint8_t	i_dur[2];
	uint8_t	i_addr1[IEEE80211_ADDR_LEN];
	uint8_t	i_addr2[IEEE80211_ADDR_LEN];
	uint8_t	i_addr3[IEEE80211_ADDR_LEN];
	uint8_t	i_seq[2];
}__attribute__((__packed__));

struct ApData{
	uint8_t		BSSID[IEEE80211_ADDR_LEN];
	int8_t		pwr;
	uint16_t	beconCnt;
	uint16_t	dataCnt;
	uint8_t		ch;
	uint8_t 	max_speed;
	uint8_t		preamble;						/* 0 = long, 1 = short */
	uint8_t		security;						/* ENC_*, AUTH_*, STD_* */
}__attribute__((__packed__));

int parse(std::map<uint32_t, struct ApData>* ApMap, const unsigned char* packet);

void DumpHex(const void* data, size_t size);

uint32_t hash_bssid(uint8_t bssid[IEEE80211_ADDR_LEN]);

void print_data(std::map<uint32_t, struct ApData>* ApMap);