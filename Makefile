all: airodump

airodump: main.o pcap.o parse802.o
	gcc -W -Wall -o airodump main.o pcap.o parse802.o -lpcap

parse802.o: parse802.c parse802.h
	gcc -c -o parse802.o parse802.c

pcap.o: pcap.c pcap.h
	gcc -c -o pcap.o pcap.c

main.o: main.c
	gcc -c -o main.o main.c

clean:
	rm *.o airodump
