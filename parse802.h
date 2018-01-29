#include <stdint.h>
#include <stdio.h>
#include <curses.h>
#include <arpa/inet.h>
#include <glog/logging.h>
#include <netinet/ether.h>
#include <map>
#include <cstring>

#define TYPE_MANAGE_FRAME 		0x0
#define TYPE_DATA_FRAME 		0x2

#define SUBTYPE_PROBE_REQUEST 	0x4
#define SUBTYPE_PROBE_RESPONSE 	0x5
#define SUBTYPE_BEACON 			0x8

#define TAG_SSID				0x00
#define TAG_SUPPORT_RATE		0x01
#define TAG_CHANNEL				0x03


#define IEEE80211_ADDR_LEN 		6
#define ESSID_MAX_LEN			33

#define MAX_STRBUF_LEN			512

struct radiotap{
    uint8_t 	h_revision;
    uint8_t 	h_pad;
    uint16_t 	h_len;
    uint32_t 	pre_flag;
}__attribute__((__packed__));

struct ieee_80211{
	uint8_t	i_ver:2, i_type:2, i_sub_type:4;
	uint8_t	i_flags;
	uint8_t	i_dur[2];
	uint8_t	i_addr1[IEEE80211_ADDR_LEN];
	uint8_t	i_addr2[IEEE80211_ADDR_LEN];
	uint8_t	i_addr3[IEEE80211_ADDR_LEN];
	uint8_t	i_seq[2];
}__attribute__((__packed__));

struct lanMng{
	uint64_t timestamp;
	uint16_t interval;
	uint16_t capInfo;
}__attribute__((__packed__));

struct bfNode{
	uint8_t		BSSID[IEEE80211_ADDR_LEN];
	uint8_t		ESSID[ESSID_MAX_LEN];
	int8_t		pwr;
	uint16_t	beconCnt;
	uint16_t	dataCnt;
	uint8_t		ch;
	uint8_t 	max_speed;
	uint8_t		preamble;						/* 0 = long, 1 = short */
	uint8_t		security;						/* ENC_*, AUTH_*, STD_* */
}__attribute__((__packed__));

int parse(std::map<uint32_t, struct bfNode*>* BfMap, const unsigned char* packet);

void DumpHex(const void* data, size_t size);

uint32_t hash_bssid(uint8_t bssid[IEEE80211_ADDR_LEN]);

void print_data(std::map<uint32_t, struct bfNode*>* BfMap);

void clearScr();