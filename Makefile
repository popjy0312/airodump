all: airodump

airodump: main.o pcap.o parse802.o savedata.o
	g++ -W -Wall -o airodump main.o pcap.o parse802.o savedata.o -lpcap -lglog -std=c++11

savedata.o: savedata.cpp savedata.h
	g++ -c -o savedata.o savedata.cpp -std=c++11

parse802.o: parse802.cpp parse802.h
	g++ -c -o parse802.o parse802.cpp -std=c++11

pcap.o: pcap.cpp pcap.h
	g++ -c -o pcap.o pcap.cpp -std=c++11

main.o: main.cpp
	g++ -c -o main.o main.cpp -std=c++11

clean:
	rm *.o airodump
