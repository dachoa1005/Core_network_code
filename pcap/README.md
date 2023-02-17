1. open terminal, cd to ./pcap/ 
2. make
3. sudo ./test để chạy chương trình 

Các step để bắt đầu capture packets\
**step 1: Find/select a default device to sniff on .**
```C
char *dev = pcap_lookupdev(errbuf);
```
pcap_lookupdev(errbuf) tìm 1 device để capture gói tin:\
    Nếu success, hàm trả về 1 con trỏ khác null trỏ vào ô nhớ chứa tên của device.\
    Nêu fail, hàm trả về con trỏ null và error message được lưu vào errbuf.

**step 2: Open device for capturing.**
2.1 Cho pcap biết mình đang sniff ở device nào \
```C
// nguyên mẫu hàm:
pcap_t *pcap_open_live(const char *device, int snaplen,
            int promisc, int to_ms, char *errbuf);

handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
```
pcap_open_live trả về giá 1 con trỏ pcap_t * nếu success và 1 con trỏ NULL nếu fail:\
    errbuf sẽ được gán giá trị của errmessage nếu fail, errbuf cũng có thể được gán warning text nếu pcap_open_live() success.\
snaplen specifies the snapshot length to be set on the handle.\
promisc specifies if the interface is to be put into promiscuous mode.\
to_ms specifies the read timeout in milliseconds.\

**step 3: Filtering packets**\
1.1 Compile filter\
```C
// nguyên mẫu hàm
int pcap_compile(pcap_t *p, struct bpf_program *fp,
        const char *str, int optimize, bpf_u_int32 netmask);

pcap_compile(handle, &fp, filter_exp, 0, net);
```
pcap_compile() được dùng để compile `filter_exp`(expression) into a BPF filter program (`*fp`).\
`optimize` \
`netmask` chỉ định Ipv4 netmask của mạng mà các gói tin đang được capture
1.2 Set the filter\
```C
// nguyên mẫu hàm
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);

pcap_setfilter(handle, &fp);
```
pcap_setfilter() dùng set the filter program as the filter for the pcap handle
**step 4: Start capture packets**
```C
int pcap_loop(pcap_t *p, int cnt,
        pcap_handler callback, u_char *user);

pcap_loop(handle, -1, got_packet, NULL);
```

