#libpcap
Libpcap là một thư viện dùng trong cho capture và process network packets. Nó cung cấp 1 API phổ biến được sử dụng rộng rãi trong các công cụ bảo mật và giám sát. 

Tương tự với libpcap, **winpcap** cũng là thư viện mã nguồn mở dùng để capture và phân tích packet dành cho Windows. Nó cho phép các ứng dụng mạng capture và truyền các gói tin bỏ qua protocol stack và đã được các chuyên gia và nhà nghiên cứu mạng sử dụng rộng rãi cho các mục đích khắc phục sự cố, phân tích và bảo mật mạng.\

Các step để bắt đầu capture packets sử dụng libpcap.\
**step 1: Find/select a default device to sniff on .**
```C
char *dev = pcap_lookupdev(errbuf);
```
`pcap_lookupdev(errbuf)` tìm 1 device để capture gói tin:\
    Nếu success, hàm trả về 1 con trỏ khác null trỏ vào ô nhớ chứa tên của device.\
    Nêu fail, hàm trả về con trỏ null và error message được lưu vào errbuf.\

**step 2: Open device for capturing.**\
2.1 Cho pcap biết mình đang sniff ở device nào.
```C
// nguyên mẫu hàm:
pcap_t *pcap_open_live(const char *device, int snaplen,
            int promisc, int to_ms, char *errbuf);

handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
```
``pcap_open_live()`` trả về giá 1 con trỏ pcap_t * nếu success và 1 con trỏ NULL nếu fail:\
    errbuf sẽ được gán giá trị của errmessage nếu fail, errbuf cũng có thể được gán warning text nếu `pcap_open_live()` success.\
snaplen specifies the snapshot length to be set on the handle.\
promisc specifies if the interface is to be put into promiscuous mode.\
to_ms specifies the read timeout in milliseconds.

**step 3: Filtering packets**\
3.1 Compile filter
```C
// nguyên mẫu hàm
int pcap_compile(pcap_t *p, struct bpf_program *fp,
        const char *str, int optimize, bpf_u_int32 netmask);

pcap_compile(handle, &fp, filter_exp, 0, net);
```
pcap_compile() được dùng để compile `filter_exp`(expression) into a BPF filter program (`*fp`).\
`optimize` \
`netmask` chỉ định Ipv4 netmask của mạng mà các gói tin đang được capture
3.2 Set the filter\
```C
// nguyên mẫu hàm
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);

pcap_setfilter(handle, &fp);
```
`pcap_setfilter()` dùng set the filter program as the filter for the pcap handle\
**step 4: Start capture packets**
```C
int pcap_loop(pcap_t *p, int cnt,
        pcap_handler callback, u_char *user);

pcap_loop(handle, -1, got_packet, NULL);
```
pcap_loop() đọc và xử lý các packets.\
`callback` đươc gọi mỗi khi `pcap_loop()` captures được 1 gói tin.\
`cnt`: -1 nghĩa là loop vô hạn, 0: loop 1 lần, n: loop n lần.

**step 5: Close session**
```C
pcap_close(handle);
```
