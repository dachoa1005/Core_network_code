# Filter packet with lib_pcap
Các step để bắt đầu capture packets sử dụng libpcap.\
**step 1: Find/select a default device to sniff on .**
```C
char *dev = pcap_lookupdev(errbuf);
```

**step 2: Open device for capturing.**\
2.1 Cho pcap biết mình đang sniff ở device nào.
```C
handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
```

**step 3: Filtering packets**\
3.1 Read filter file into filter_exp
```C
// Open bpf_filter file to read 
FILE *bpf_file = fopen("filter.bpf", "r");

// Determine the size of the file
fseek(bpf_file, 0, SEEK_END);
size = ftell(bpf_file);
rewind(bpf_file);

// Allocate memory to hold the filter expression
filter_exp = malloc(size + 1);

// Read the filter expression from the file
fread(filter_exp, 1, size, bpf_file) != size

// Add a null terminator to the filter expression
filter_exp[size] = '\0';
```
3.2 Compile filter
```C
pcap_compile(handle, &fp, filter_exp, 0, net);
```

3.2 Set the filter
```C
pcap_setfilter(handle, &fp);
```

**step 4: Start capture packets**
```C
pcap_loop(handle, -1, process_packet, NULL);
```

`process_packet()` đươc gọi mỗi khi capture được 1 packet thỏa mãn filter:\
Lấy ra `ethernet_header` để từ đó kiểm tra xem đây có phải là IP packet hay không\
```C
ethernet_header = (struct ether_header *)packet;
```
Sử dụng điều kiện `ntohs(ethernet_header->ether_type) == ETHERTYPE_IP` để chỉ thao tác với các IP packet\
Lấy `ip_header` từ packet để từ đó lấy ra được các thông tin của file (source, dest IP, MAC, ...)
```C
ip_header = (struct ip *)(packet + ethernet_header_length);
```
Convert dest,source ip từ dạng 32-bit thành string\
```C
inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
```

Convert protocol_number thành tên (ví dụ: protocol_name = 6 chuyển thành TCP)
```C
struct protoent *protocol = getprotobynumber(ip_header->ip_p);
```

Viết tất cả vào file log:
```C
fp = fopen("log.txt", "a");
        fprintf(fp, "Protocol: %s, Source IP: %15s, Destination IP: %15s, Source MAC: %02x:%02x:%02x:%02x:%02x:%02x, Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                protocol->p_name, source_ip, dest_ip,
                ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2],
                ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5],
                ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2],
                ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
        fclose(fp);
```
**step 5: Close session**
```C
pcap_close(handle);
```
