# Encypted Chat Group
1. Cd đến Server
2. Chạy lệnh: `make`
3. Chạy lệnh: `./server`
4. Mở n terminal mới
5. Mỗi terminal Cd đến Client
6. Chạy lệnh: `./client`

## Giải thích code
### Server
1. Định nghĩa struct `client` chứa thông tin của client:
```c
typedef struct
{
    int sockfd;
    char *name;
    RSA *rsa_pub_key;
} Client;
```

2. Định nghĩa struct `Encrypted_message` chứa thông tin của tin nhắn:
```c
typedef struct
{
    int len;
    char encypted_message[1024];
} Encrypted_message;
```

3. Tạo 1 mảng `clients` chứa các client đang kết nối, khởi tạo mảng với mỗi client có sockfd = -1, name = NULL, rsa_pub_key = NULL

4. Generate RSA key cho server:
```c
int bits = 1024;
    int ret = 0;
    BIGNUM *bne = NULL;

    unsigned long e = RSA_F4;

    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        printf("Create RSA key fail.\n");
        exit(EXIT_FAILURE);
    }

    server_rsa_key = RSA_new();
    ret = RSA_generate_key_ex(server_rsa_key, bits, bne, NULL);
    if (ret != 1)
    {
        printf("Create RSA key fail.\n");
        exit(EXIT_FAILURE);
    }
```

5. Lưu server public key dưới dạng xâu (để gửi cho mỗi client)
```c
bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, server_rsa_key, NULL, NULL, 0, NULL, NULL);

    server_pri_key_len = BIO_get_mem_data(bio, &server_pri_key);
    server_pri_key[server_pri_key_len] = '\0';
```

