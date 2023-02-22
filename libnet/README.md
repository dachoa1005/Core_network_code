# libnet
Libnet là một API(toolkit) cấp cao cho phép lập trình viên xây dựng và inject network packets trong môi trường LINUX. Nó cung cấp portable framework dể  viết và xử lý gói mạng cấp thấp (low-level network packet) 

Các bước để tạo gói tin ICMP dử dụng libneb

1. Init libnet - create libnet context
```C
    l = libnet_init(LIBNET_RAW4, "ens33", libnet_errbuf);
```
Create libnet environment, 
`LIBNET_RAW4` - injection type, the function initializes the injection primitives for the IPv4 raw socket interface.\
`ens33` tên device.\
`libnet_errbuf` chứa error message nếu function fails.\

2. Generating random id 
```C
    libnet_seed_prand (l);
    id = (u_int16_t)libnet_get_prand(LIBNET_PR16);
```

3. Get destination IP address 
```C
    dst_ip = libnet_name2addr4(l, "192.168.10.194", LIBNET_DONT_RESOLVE); 
    src_ip = libnet_name2addr4(l, "192.168.131.130", LIBNET_DONT_RESOLVE);
```
`libnet_name2addr4()` chuyển địa chỉ IP từ dạng string thành địa chỉ IP có cấu trúc `net_addr`.\
`LIBNET_DONT_RESOLVE` để chỉ định hàm không cần giải quyết tên miền (chỉ là chuyển IP từ dạng string thành net_addr).\

4. Build ICMP header 
```C
icmp_tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq,     
                                  (u_int8_t*)payload, sizeof(payload), l, 0);
```
`libnet_build_icmpv4_echo()` return protocoltag on succes, -1 on error
`ICMP_ECHO` - type of ICMP packet.\ 
`0` - code of ICMP packet.\
`0` - checksum.\
`id` - identification number - được tạo random ở trên.\
`seq` - packet sequence number.\
`payload` - optinal payload or NULL.\
`l` - pointer to a libnet context.\
`0` - protocol tag to modify an existing header, 0 to build a new on

5. Build IP header 
```C
ip_tag = libnet_build_ipv4( LIBNET_IPV4_H + 
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
                            0)
```

6. Writing packet
```C
    libnet_write(l);
```
`libnet_write()` Writes a prebuilt packet to the network. The function assumes that l was previously initialized (via a call to libnet_init()) and that a previously constructed packet has been built inside this context 

7. Updating ICMP header, reusing buffers allocated in l with icmp_tag
```C
for ( i = 0; i < 4; i++ ) {      
    icmp_tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq+i,     
                                        (u_int8_t*)payload, sizeof(payload), 
                                        l, icmp_tag);
    libnet_write(l) ;
}
```
