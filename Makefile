all: airodump

airodump: main.o pcap.o parse802.o
	g++ -W -Wall -o airodump main.o pcap.o parse802.o -lpcap -lglog

savedata.o: savedata.cpp savedata.h
	g++ -c -o savedata.o savedata.cpp

parse802.o: parse802.cpp parse802.h
	g++ -c -o parse802.o parse802.cpp

pcap.o: pcap.cpp pcap.h
	g++ -c -o pcap.o pcap.cpp

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm *.o airodump
