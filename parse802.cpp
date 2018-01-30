#include "parse802.h"

int parse(mymap* BfMap, char* packet, uint32_t caplen){
	struct radiotap* 		radioHeader = (struct radiotap*)packet;
	struct ieee_80211*		pieee;
	struct lanMng*			planMng;
	char*					ptmp;
	uint8_t					tagNum;
	uint8_t					tagLen;
	uint16_t				offset;
	uint16_t				CipherSuiteCnt;
	uint16_t				AKMCnt;
	uint16_t				i;
	uint8_t					flag;

	struct bfNode*			ptmpNode;
	mymap::iterator it;

/*
	DumpHex(packet,32);
	LOG(INFO) << "h_len is "<< radioHeader->h_len;
	printf("------------------------------------------------------\n");
*/
	pieee = (struct ieee_80211*)(packet + radioHeader->h_len); 

	switch(pieee->i_type){
		case TYPE_MANAGE_FRAME:
			if(pieee->i_sub_type == SUBTYPE_BEACON){
				it = BfMap->find( *(struct addr*)(pieee->i_addr3));
				if(it != BfMap->end()){
					//LOG(INFO) << "already";
					ptmpNode = it->second;
					ptmpNode->beconCnt++;
				}
				else{
					LOG(INFO) << "insert new node";

					ptmpNode = (struct bfNode*)malloc(sizeof(struct bfNode));

					//memcpy_s(ptmpNode->BSSID,IEEE80211_ADDR_LEN, pieee->i_addr3, IEEE80211_ADDR_LEN);
					memcpy(ptmpNode->BSSID, pieee->i_addr3, IEEE80211_ADDR_LEN);

					ptmpNode->pwr = -1;
					ptmpNode->beconCnt = 1;
					ptmpNode->dataCnt = 0;
					ptmpNode->security = 0;
					ptmpNode->max_speed = 0;


					BfMap->insert(std::pair<struct addr, struct bfNode*>(*(struct addr*)(pieee->i_addr3), ptmpNode));
					LOG(INFO) << "insert ok";
				}

				planMng = (struct lanMng*)((char*)pieee + sizeof(struct ieee_80211));
				if((planMng->capInfo & 0x10) >> 4) ptmpNode->security |= STD_WEP|ENC_WEP;
				else ptmpNode->security |= STD_OPN;

				ptmpNode->preamble = (planMng->capInfo & 0x20) >> 5;

				ptmp = (char*)planMng + sizeof(struct lanMng);

				while(ptmp - packet + 4< caplen){		// frame check sequence 4 bytes
					flag = 0;
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
							ptmpNode->max_speed = (uint8_t)std::max(ptmpNode->max_speed, (uint8_t)(*(ptmp + tagLen - 1) / 2));
							break;
						case TAG_CHANNEL:
							ptmpNode->ch = *(ptmp + tagLen - 1);
							break;
						case TAG_RSN_INFO:
							ptmpNode->security |= STD_WPA2;
							offset = 6;
							flag = 1;
							break;
						case TAG_EXTEND_SUPPORT_RATE:
							ptmpNode->max_speed = (uint8_t)std::max(ptmpNode->max_speed, (uint8_t)(*(ptmp + tagLen - 1) / 2));
							break;
						case TAG_VEND_SPECIFIC:
							if(tagLen >= 8 && (memcmp(ptmp, "\x00\x50\xF2\x01\x01\x00", 6) == 0)){
								ptmpNode->security |= STD_WPA;
								offset = 10;
								flag = 1;
							}
							break;
					}

					if(flag){
						ptmpNode->security &= ~(STD_WEP|ENC_WEP|STD_WPA);
						CipherSuiteCnt = *(uint16_t*)(ptmp + offset);
						offset += 5;
						for(i=0;i<CipherSuiteCnt;i++){
							switch(*(ptmp + offset + i*4)){
								case 0x01:
									ptmpNode->security |= ENC_WEP;
									break;
								case 0x02:
									ptmpNode->security |= ENC_TKIP;
									break;
								case 0x03:
									ptmpNode->security |= ENC_WRAP;
									break;
								case 0x04:
									ptmpNode->security |= ENC_CCMP;
									break;
								case 0x05:
									ptmpNode->security |= ENC_WEP104;
									break;
								default:
									break;
							}
						}
						AKMCnt = *(uint16_t*)(ptmp + offset + 4*CipherSuiteCnt - 3);
						offset += 2 + 4*CipherSuiteCnt;
						for(i=0;i<CipherSuiteCnt;i++){
							switch(*(ptmp + offset + i*4)){
								case 0x01:
									ptmpNode->security |= AUTH_MGT;
									break;
								case 0x02:
									ptmpNode->security |= AUTH_PSK;
									break;
								default:
									break;
							}
						}
						flag = 0;
					}

					ptmp += tagLen;
				}
			}

			break;

		case TYPE_DATA_FRAME:
			LOG(INFO) << "TYPE_DATA_FRAME";

			it = BfMap->find( *(struct addr*)(pieee->i_addr3));
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

void print_data(mymap* BfMap){
	char				strbuf[MAX_STRBUF_LEN];
	uint32_t 			len = 0;
	struct bfNode* 		ptmpNode;

	#if defined(DEBUG)
		clearScr();
	#else
		clear();
    #endif

	#if defined(DEBUG)
		printf(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
	#else
		printw(" BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");
    #endif

	for(mymap::iterator it= BfMap->begin(); it != BfMap->end(); it++){
		//LOG(INFO) << BfMap->size();
		ptmpNode = it->second;
		memset(strbuf, '\0', MAX_STRBUF_LEN);
		snprintf( strbuf, sizeof(strbuf), " %02X:%02X:%02X:%02X:%02X:%02X",
			ptmpNode->BSSID[0], ptmpNode->BSSID[1],
			ptmpNode->BSSID[2], ptmpNode->BSSID[3],
			ptmpNode->BSSID[4], ptmpNode->BSSID[5] );
		len = strlen(strbuf);

		snprintf( strbuf + len, sizeof(strbuf) - len, "  %3d %8d %8d %4d %3d %3d%c%c ", 
			ptmpNode->pwr,
			ptmpNode->beconCnt,
			ptmpNode->dataCnt,
			0,
			ptmpNode->ch,
			ptmpNode->max_speed,
			ptmpNode->security?'e' : ' ',
			ptmpNode->preamble?'.' : ' ');

		len = strlen(strbuf);

		if( (ptmpNode->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) snprintf( strbuf+len, sizeof(strbuf)-len, "     " );
		else if( ptmpNode->security & STD_WPA2 ) snprintf( strbuf+len, sizeof(strbuf)-len, "WPA2" );
		else if( ptmpNode->security & STD_WPA  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WPA " );
		else if( ptmpNode->security & STD_WEP  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP " );
		else if( ptmpNode->security & STD_OPN  ) snprintf( strbuf+len, sizeof(strbuf)-len, "OPN " );

		len = strlen(strbuf);

		if( (ptmpNode->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) snprintf( strbuf+len, sizeof(strbuf)-len, "        ");
		else if( ptmpNode->security & ENC_CCMP   ) snprintf( strbuf+len, sizeof(strbuf)-len, " CCMP   ");
		else if( ptmpNode->security & ENC_WRAP   ) snprintf( strbuf+len, sizeof(strbuf)-len, " WRAP   ");
		else if( ptmpNode->security & ENC_TKIP   ) snprintf( strbuf+len, sizeof(strbuf)-len, " TKIP   ");
		else if( ptmpNode->security & ENC_WEP104 ) snprintf( strbuf+len, sizeof(strbuf)-len, " WEP104 ");
		else if( ptmpNode->security & ENC_WEP40  ) snprintf( strbuf+len, sizeof(strbuf)-len, " WEP40  ");
		else if( ptmpNode->security & ENC_WEP	) snprintf( strbuf+len, sizeof(strbuf)-len, " WEP	");

		len = strlen(strbuf);

		if( (ptmpNode->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) snprintf( strbuf+len, sizeof(strbuf)-len, "    ");
		else if( ptmpNode->security & AUTH_MGT   ) snprintf( strbuf+len, sizeof(strbuf)-len, " MGT");
		else if( ptmpNode->security & AUTH_PSK   )
		{
		if( ptmpNode->security & STD_WEP )
			snprintf( strbuf+len, sizeof(strbuf)-len, "SKA ");
		else
			snprintf( strbuf+len, sizeof(strbuf)-len, "PSK ");
		}
		else if( ptmpNode->security & AUTH_OPN   ) snprintf( strbuf+len, sizeof(strbuf)-len, " OPN");

		len = strlen(strbuf);

		snprintf( strbuf + len, sizeof(strbuf) - len, " %s",
			ptmpNode->ESSID);

		#if defined(DEBUG)
			printf("%s\n", strbuf);
		#else
			printw("%s\n", strbuf);
    	#endif
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