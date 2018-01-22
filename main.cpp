#include <pcap.h>
#include <stdio.h>
#include <glog/logging.h>

int main(int argc, char** argv){
    char*                   dev;
    pcap_t*                 handle;
    char                    errbuf[PCAP_ERRBUF_SIZE];
    const u_char*           packet;
    struct pcap_pkthdr*     pheader;
    uint32_t                res;

    if(argc != 2){
        printf("usage: airodump <interface>\n");
        return 1;
    }
    dev = argv[1];
    if ((handle = pcap_create(dev, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    if(pcap_set_rfmon(handle, 1) == PCAP_ERROR_ACTIVATED){
        fprintf(stderr, "set rfmon error\n");
        return 1;
    }
    if(pcap_activate(handle) != 0){
        fprintf(stderr, "Error activate handle %s", pcap_geterr(handle));
        return 1;
    }
    while( (res = pcap_next_ex(handle, &pheader, &packet)) >= 0){
        if (res == 0)
            continue;
        printf("len %d\n", pheader->len);
    }
    return 0;
}
