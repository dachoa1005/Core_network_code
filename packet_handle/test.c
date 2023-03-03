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

int main(int argc, char const *argv[])
{
    char *filter_exp;
    long size;

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
    if (filter_exp == NULL)
    {
        fprintf(stderr, "Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    // Read the filter expression from the file
    if (fread(filter_exp, 1, size, file) != size)
    {
        fprintf(stderr, "Error reading filter file\n");
        exit(EXIT_FAILURE);
    }

    // Add a null terminator to the filter expression
    filter_exp[size] = '\0';

    // print the filter expression
    printf("%s\n", filter_exp);
    
    // Close the filter file
    fclose(file);
    return 0;
}
