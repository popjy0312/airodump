#include "pcap.h"
#include "savedata.h"

int main(int argc, char** argv){
	char*							   dev;
	pcap_t*                            handle;
	char							   errbuf[PCAP_ERRBUF_SIZE];
	char*                              packet;
	struct pcap_pkthdr*                pheader;
	uint32_t                           res;
	mymap                              BfMap;

	google::InitGoogleLogging(argv[0]);

	#if defined(DEBUG)
    	FLAGS_alsologtostderr = 1;
	#else
    	initscr();
    #endif


	if(argc != 2){
		LOG(ERROR) << "usage: ./airodump <interface>";
		return 1;
	}
	dev = argv[1];
	if ((handle = pcap_create(dev, errbuf)) == NULL) {
		LOG(FATAL) << "Couldn't open device " << dev << ": " <<errbuf;
		return 1;
	}
	if(pcap_set_rfmon(handle, 1) == PCAP_ERROR_ACTIVATED){
		LOG(FATAL) << "set rfmon fail";
		return 1;
	}
	if(pcap_activate(handle) != 0){
		LOG(FATAL) << "Fail activate handle " << pcap_geterr(handle);
		return 1;
	}
	while( (res = pcap_next_ex(handle, &pheader, (const unsigned char**)&packet)) >= 0){
		if (res == 0)
			continue;
		//LOG(INFO) << "len " << pheader->len;
		parse(&BfMap, packet, pheader->len);
	}

	google::ShutdownGoogleLogging();
	#if defined(DEBUG)
    	endwin();
    #endif
	return 0;
}
