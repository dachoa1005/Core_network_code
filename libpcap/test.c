#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	printf("Got a packet\n");
}

int main()
{
	pcap_t *handle;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;

	// Step 1: Find/select a default device to sniff on 
	
	// pcap_findalldevs(&dev, errbuf);
	dev = pcap_lookupdev(errbuf); 
	// find a default device on which to capture, errbuf used to return error message

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	
	// Step 2: Open device for sniffing
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "Couldn't  open device %s: %s\n", dev, errbuf);
		return(2);	
	}

	// Step 3: Filtering packets
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	// Step 4: Start capture packets
	pcap_loop(handle, -1, got_packet, NULL); // Capture packets and call got_packet() for each packet captured
	
	// Step 5: Close session
	pcap_close(handle);   //Close the handle
	return 0;
}