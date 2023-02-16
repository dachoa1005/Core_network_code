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

	// Find default device 
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	// Step 1: Open live pcap session on NIC with name enp0s3
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "Couldn't  open device %s: %s\n", dev, errbuf);
		return(2);	
	}

	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);   //Close the handle
	return 0;
}