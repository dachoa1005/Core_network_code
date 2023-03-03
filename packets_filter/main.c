#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev,  *filter_file;
    pcap_t *handle;
    struct bpf_program fp;
    char *filter_exp;
    bpf_u_int32 mask, net;
    int num_packets;
    long size;

    if (argc != 2)
    {
        printf("Usage: %s interface\n", argv[0]);
        exit(1);
    }

    dev = argv[1];
    
    // read filter file in to filter_exp
    FILE *file = fopen("filter.bpf", "r");
    if (file == NULL)
    {
        printf("Error opening filter file\n");
        exit(1);
    }

     // Determine the size of the file
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    // Allocate memory to hold the filter expression
    filter_exp = malloc(size + 1);
    if (filter_exp == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    // Read the filter expression from the file
    if (fread(filter_exp, 1, size, file) != size) {
        fprintf(stderr, "Error reading filter file\n");
        exit(EXIT_FAILURE);
    }

    // Add a null terminator to the filter expression
    filter_exp[size] = '\0';

    // Print the filter expression
    printf("%s\n", filter_exp);

    // Close the filter file
    fclose(file);

    

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Error getting network mask for %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Error opening interface %s: %s\n", dev, errbuf);
        exit(1);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("Error compiling BPF filter: %s\n", pcap_geterr(handle));
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error setting BPF filter: %s\n", pcap_geterr(handle));
        exit(1);
    }

    // pcap_freealldevs(alldevs);
    // pcap_freefilter(&fp);

    pcap_loop(handle, num_packets, process_packet, NULL);

    pcap_close(handle);

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ethernet_header;
    struct ip *ip_header;
    int ethernet_header_length, ip_header_length;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    FILE *fp;

    ethernet_header = (struct ether_header *)packet;
    ethernet_header_length = sizeof(struct ether_header);

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) // only process IP packets
    {
        ip_header = (struct ip *)(packet + ethernet_header_length);
        ip_header_length = ip_header->ip_hl * 4;

        // Convert protocol_number into name
        struct protoent *protocol = getprotobynumber(ip_header->ip_p);
        if (protocol == NULL) {
            printf("Error: Unknown protocol number\n");
            return;
        }

        // Convert source and destination IP addresses to strings
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // Log packet information
        fp = fopen("log.txt", "a");
        fprintf(fp, "Protocol: %s, Source IP: %15s, Destination IP: %15s, Source MAC: %02x:%02x:%02x:%02x:%02x:%02x, Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                protocol->p_name, source_ip, dest_ip,
                ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2],
                ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5],
                ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2],
                ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
        fclose(fp);
    }
}