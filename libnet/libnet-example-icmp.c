#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <stdint.h>

int main() 
{
     libnet_t *l;  /* libnet context */
     char libnet_errbuf[LIBNET_ERRBUF_SIZE];
     u_int32_t src_ip, dst_ip;
     u_int16_t id, seq;
     char payload[] = "libnet :D";
     int bytes_written;
     int i;
     libnet_ptag_t ip_tag, icmp_tag;
     // char *dev, pcap_errbuf[PCAP_ERRBUF_SIZE];

     // dev = pcap_lookupdev(pcap_errbuf);
	// if (dev == NULL) {
	// 	fprintf(stderr, "Couldn't find default device: %s\n", pcap_errbuf);
	// 	return(2);
	// }
     // printf("Device: %s\n", dev);

     l = libnet_init(LIBNET_RAW4, "ens33", libnet_errbuf);
     if ( l == NULL ) {
          fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
          exit(EXIT_FAILURE);
     }

     /* Generating a random id */
     libnet_seed_prand (l);
     id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

     /* Getting destination IP address */
     dst_ip = libnet_name2addr4(l, "192.168.131.1", LIBNET_DONT_RESOLVE); 
     src_ip = libnet_name2addr4(l, "192.168.131.130", LIBNET_DONT_RESOLVE);

     if ( dst_ip == -1 || src_ip == -1 ) {
          fprintf(stderr, "Error converting IP address.\n");
          libnet_destroy(l);
          exit(EXIT_FAILURE);
     }

     /* Building ICMP header */

     seq = 1;

     if( (icmp_tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq,     
                                  (u_int8_t*)payload, sizeof(payload), l, 0)) == -1)
     {
          fprintf(stderr, "Error building ICMP header: %s\n", libnet_geterror(l));
          libnet_destroy(l);
          exit(EXIT_FAILURE);
     }

     /* Building IP header 
      * Shorter version:
      *   if (libnet_autobuild_ipv4(LIBNET_IPV4_H +                        
      *                             LIBNET_ICMPV4_ECHO_H + sizeof(payload), 
      *                             IPPROTO_ICMP, ip_addr, l) == -1 ) 
      */
     if( (ip_tag = 
          libnet_build_ipv4( LIBNET_IPV4_H + 
                             LIBNET_ICMPV4_ECHO_H + sizeof(payload), // total packet size
                             0,   // tos
                             libnet_get_prand(LIBNET_PRu16), // id
                             0,   // frag
                             64,  // ttl
                             IPPROTO_ICMP,
                             0,   // checksum,
                             src_ip,
                             dst_ip, 
                             NULL,  // payload pointer 
                             0,     // payload size
                             l,     // libnet context
                             0)) == -1 )    // ptag
     {
          fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(l));
          libnet_destroy(l);
          exit(EXIT_FAILURE);
     }

     /* Writing packet */
     
     bytes_written = libnet_write(l);
     if ( bytes_written != -1 )
          printf("%d bytes written.\n", bytes_written);
     else
          fprintf(stderr, "Error writing packet: %s\n", \
                  libnet_geterror(l));

     /* Updating the ICMP header, reusing buffers allocated in l with icmp_tag */
     for ( i = 0; i < 4; i++ ) {
          
          icmp_tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq+i,     
                                              (u_int8_t*)payload, sizeof(payload), 
                                              l, icmp_tag);
          
          if (icmp_tag == -1) {
               fprintf(stderr, "Error building ICMP header: %s\n", libnet_geterror(l));
               libnet_destroy(l);
               exit(EXIT_FAILURE);
          }
          
          if ( libnet_write(l) == -1 )
               fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
          
          /* Waiting 1 second between each packet */
          sleep(1);
     }


     libnet_destroy(l);
     return 0;
}