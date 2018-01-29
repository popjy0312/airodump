#include "parse802.h"

int parse(std::map<uint32_t, struct bfNode*>* BfMap, const unsigned char* packet){
	struct radiotap* 	radioHeader = (struct radiotap*)packet;
	struct ieee_80211*		pieee;
	struct lanMng*		planMng;
	char*				ptmp;
	uint8_t				tagNum;
	uint8_t				tagLen;
	uint8_t				flag;

	struct bfNode*		ptmpNode;
	std::map<uint32_t, struct bfNode*>::iterator it;

	DumpHex(packet,32);
	LOG(INFO) << "h_len is "<< radioHeader->h_len;

	pieee = (struct ieee_80211*)(packet + radioHeader->h_len); 

	switch(pieee->i_type){
		case TYPE_MANAGE_FRAME:
			if(pieee->i_sub_type == SUBTYPE_BEACON){
				it = BfMap->find( hash_bssid(pieee->i_addr3));
				if(it != BfMap->end()){
					//LOG(INFO) << "already";
					it->second->beconCnt++;
				}
				else{
					LOG(INFO) << "insert new node";

					ptmpNode = (struct bfNode*)malloc(sizeof(struct bfNode));

					//memcpy_s(ptmpNode->BSSID,IEEE80211_ADDR_LEN, pieee->i_addr3, IEEE80211_ADDR_LEN);
					memcpy(ptmpNode->BSSID, pieee->i_addr3, IEEE80211_ADDR_LEN);

					ptmpNode->pwr = -1;
					ptmpNode->beconCnt = 1;
					ptmpNode->dataCnt = 0;

					planMng = (struct lanMng*)((char*)pieee + sizeof(struct ieee_80211));

					ptmpNode->security = (planMng->capInfo & 0x10) >> 4;

					ptmpNode->preamble = (planMng->capInfo & 0x20) >> 5;

					ptmp = (char*)planMng + sizeof(struct lanMng);

					flag = 1;
					while(flag){
						tagNum = *ptmp;
						tagLen = *(ptmp + 1);
						ptmp += 2;

						switch(tagNum){
							case TAG_SSID:
								//memcpy_s(ptmpNode->ESSID, ESSID_MAX_LEN, ptmp, tagLen);
								memcpy(ptmpNode->ESSID, ptmp, tagLen);
								ptmpNode->ESSID[tagLen] = 0;
								break;
							case TAG_SUPPORT_RATE:
								ptmpNode->max_speed = *(ptmp + tagLen - 1) / 2;
								break;
							case TAG_CHANNEL:
								ptmpNode->ch = *(ptmp + tagLen - 1);
								break;
							default:
								flag = 0;
						}

						ptmp += tagLen;
					}

					BfMap->insert(std::pair<uint32_t, struct bfNode*>(hash_bssid(pieee->i_addr3), ptmpNode));
					LOG(INFO) << "insert ok";
				}
			}

			break;

		case TYPE_DATA_FRAME:
			LOG(INFO) << "TYPE_DATA_FRAME";

			it = BfMap->find( hash_bssid(pieee->i_addr3));
			if(it != BfMap->end()){
				LOG(INFO) << "already";
				it->second->dataCnt++;
			}
			else{
			}

			break;
	}



/*
		case SUBTYPE_PROBE_REQUEST:
			LOG(INFO) << "SUBTYPE_PROBE_REQUEST";
			break;

		case SUBTYPE_PROBE_RESPONSE:
			LOG(INFO) << "SUBTYPE_PROBE_RESPONSE";
			break;
*/

	print_data(BfMap);
	return 0;
}

void print_data(std::map<uint32_t, struct bfNode*>* BfMap){
	char				strbuf[MAX_STRBUF_LEN];
	uint32_t 			len = 0;
	struct bfNode* 		ptmpNode;

	//clearScr();

	printf(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
	for(std::map<uint32_t, struct bfNode*>::iterator it= BfMap->begin(); it != BfMap->end(); it++){
		//LOG(INFO) << BfMap->size();
		ptmpNode = it->second;
		memset(strbuf, '\0', MAX_STRBUF_LEN);
	    snprintf( strbuf, sizeof(strbuf), " %02X:%02X:%02X:%02X:%02X:%02X",
	    	ptmpNode->BSSID[0], ptmpNode->BSSID[1],
	    	ptmpNode->BSSID[2], ptmpNode->BSSID[3],
	    	ptmpNode->BSSID[4], ptmpNode->BSSID[5] );
	    len = strlen(strbuf);

	    snprintf( strbuf + len, sizeof(strbuf) - len, "  %3d %8d %8d %4d %3d %3d%c%c", 
	    	ptmpNode->pwr,
	    	ptmpNode->beconCnt,
	    	ptmpNode->dataCnt,
	    	0,
	    	ptmpNode->ch,
	    	ptmpNode->max_speed,
	    	ptmpNode->security?'e' : ' ',
	    	ptmpNode->preamble?'.' : ' ');

	    len = strlen(strbuf);

	    snprintf( strbuf + len, sizeof(strbuf) - len, " %-4s %-6s %-4s %s",
	    	"AAA",
	    	"AAA",
	    	"AAA",
	    	ptmpNode->ESSID);

	    printf("%s\n", strbuf);
	    //LOG(INFO) << ptmpNode->beconCnt;
	    refresh();
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

void clearScr(){
	int i;
	for(i=0;i<5;i++)
		printf("\n\n\n\n\n\n\n\n\n");
}