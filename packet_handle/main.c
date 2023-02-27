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

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev, *bpf_filter, *filter_file;
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask, net;
    int num_packets;

    if (argc != 4)
    {
        printf("Usage: %s interface bpf_filter filter_file\n", argv[0]);
        exit(1);
    }

    dev = argv[1];
    bpf_filter = argv[2];
    filter_file = argv[3];

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

    if (pcap_compile(handle, &fp, bpf_filter, 0, net) == -1)
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
    pcap_freefilter(&fp);

    pcap_loop(handle, num_packets, process_packet, (u_char *)filter_file);

    pcap_close(handle);

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char *filter_file = (char *)args;
    struct ether_header *ethernet_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    int ethernet_header_length, ip_header_length, tcp_header_length, udp_header_length, icmp_header_length;
    const u_char *payload;
    int payload_length;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    FILE *fp;

    ethernet_header = (struct ether_header *)packet;
    ethernet_header_length = sizeof(struct ether_header);

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        ip_header = (struct ip *)(packet + ethernet_header_length);
        ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            tcp_header = (struct tcphdr *)(packet + ethernet_header_length + ip_header_length);
            tcp_header_length = tcp_header->th_off * 4;

            payload = packet + ethernet_header_length + ip_header_length + tcp_header_length;
            payload_length = ntohs(ip_header->ip_len) - ip_header_length - tcp_header_length;

            // Log TCP payload if it contains application layer protocol data
            if (payload_length > 0)
            {
                if (strncmp(filter_file, "tcp", 3) == 0)
                {
                    fp = fopen("log.txt", "a");
                    fprintf(fp, "TCP: %.*s\n", payload_length, payload);
                    fclose(fp);
                }
            }
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            udp_header = (struct udphdr *)(packet + ethernet_header_length + ip_header_length);
            udp_header_length = sizeof(struct udphdr);

            payload = packet + ethernet_header_length + ip_header_length + udp_header_length;
            payload_length = ntohs(udp_header->uh_ulen) - udp_header_length;

            // Log UDP payload if it contains application layer protocol data
            if (payload_length > 0)
            {
                if (strncmp(filter_file, "udp", 3) == 0)
                {
                    fp = fopen("log.txt", "a");
                    fprintf(fp, "UDP: %.*s\n", payload_length, payload);
                    fclose(fp);
                }
            }
        }
        else if (ip_header->ip_p == IPPROTO_ICMP)
        {
            icmp_header = (struct icmphdr *)(packet + ethernet_header_length + ip_header_length);
            icmp_header_length = sizeof(struct icmphdr);

            // Log ICMP packet
            if (strncmp(filter_file, "icmp", 4) == 0)
            {
                fp = fopen("log.txt", "a");
                fprintf(fp, "ICMP: type=%d, code=%d\n", icmp_header->type, icmp_header->code);
                fclose(fp);
            }
        }

        // Convert source and destination IP addresses to strings
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // Log packet information
        fp = fopen("log.txt", "a");
        fprintf(fp, "Protocol: %d, Source IP: %s, Destination IP: %s, Source MAC: %02x:%02x:%02x:%02x:%02x:%02x, Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                ip_header->ip_p, source_ip, dest_ip,
                ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2],
                ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5],
                ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2],
                ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
        fclose(fp);
    }
}