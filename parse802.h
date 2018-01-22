#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <glog/logging.h>
#include <netinet/ether.h>

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

int parse(const unsigned char* packet);

void DumpHex(const void* data, size_t size);
