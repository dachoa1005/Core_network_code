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
- `len`: độ dài của tin nhắn đã được mã hóa.
- `encypted_message`: tin nhắn đã được mã hóa.

3. Tạo 1 mảng `clients` chứa các client đang kết nối, khởi tạo mảng với mỗi client có `sockfd = -1`, `name = NULL`, `rsa_pub_key = NULL`

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
- bits: độ dài của key.
- bne: số nguyên tố dùng để mã hóa.
- server_rsa_key: key được tạo ra để mã hóa/giải mã (chứa cặp public key, private key).

5. Lưu server public key dưới dạng xâu (để gửi cho mỗi client)
```c
bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, server_rsa_key, NULL, NULL, 0, NULL, NULL);

    server_pri_key_len = BIO_get_mem_data(bio, &server_pri_key);
    server_pri_key[server_pri_key_len] = '\0';
```
- Hàm `BIO_new(BIO_s_mem())` tạo ra 1 BIO mới để lưu server public key, BIO_s_mem() là 1 loại BIO dùng để lưu trữ dữ liệu trong bộ nhớ.
- Hàm `PEM_write_bio_RSAPrivateKey` lưu server public key vào BIO.
- Hàm `BIO_get_mem_data` lấy dữ liệu từ BIO và lưu vào biến `server_pri_key`.

6. Định nghĩa các hàm send_struct, recv_struct để gửi, nhận struct qua socket:
```c
int send_struct(int sockfd, Encrypted_message *message)
{
    char *buffer = (char *)message;
    int total_bytes_sent = 0;
    int bytes_left_to_send = sizeof(Encrypted_message);
    int bytes_sent = 0;
    while (total_bytes_sent < sizeof(Encrypted_message))
    {
        bytes_sent = send(sockfd, buffer + total_bytes_sent, bytes_left_to_send, 0);
        if (bytes_sent == -1)
        {
            return -1;
        }
        total_bytes_sent += bytes_sent;
        bytes_left_to_send -= bytes_sent;
    }

    return total_bytes_sent;
}

int recv_struct(int sockfd, Encrypted_message *message)
{

    char *buffer = (char *)message;
    int total_bytes_received = 0;
    int bytes_left_to_recv = sizeof(Encrypted_message);
    int bytes_recv = 0;
    while (total_bytes_received < sizeof(Encrypted_message))
    {
        bytes_recv = recv(sockfd, buffer + total_bytes_received, bytes_left_to_recv, 0);
        if (bytes_recv == -1)
        {
            return -1;
        }
        else if (bytes_recv == 0)
        {
            return 0;
        }
        total_bytes_received += bytes_recv;
        bytes_left_to_recv -= bytes_recv;
    }

    return total_bytes_received;
}
```
- Dùng buffer để lưu địa chỉ của struct, sau đó dùng vòng lặp để gửi, nhận struct, đối với buffer có độ vượt quá 1024 byte thì sẽ gửi, nhận từng phần của buffer qua socket.

7. Dùng vòng lặp để chờ client kết nối:
    - Mỗi khi có client kết nối đến server, dùng kết quả của hàm `accept` lưu sockfd của client vào mảng `clients`.
    - Gửi public key của server cho client và nhận public key của client đó.
    - Tạo 1 thread mới để xử lý client mới, truyền vào sockfd của client đó. Hàm xử lý client:
        - Dùng struct `Encrypted_message` để nhận tên (username) của client, giải mã tên đó và lưu vào mảng `clients`.
```C
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].sockfd == socket)
            {
                clients[i].name = malloc(strlen(dec_message) + 1);
                strcpy(clients[i].name, dec_message);
                client_name = malloc(strlen(dec_message) + 1);
                strcpy(client_name, dec_message);
            }
        }
```

        - Dùng vòng lặp do...while để nhận tin nhắn từ client, giải mã bằng server private key sau đó mã hóa lại bằng public key của mỗi client rồi chuyển tiếp đến các clients đang kết nối đến server (sử dụng sockfd của mỗi client được lưu trong mảng clients).

```c
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].sockfd != socket && clients[i].sockfd != -1)
            {
                Encrypted_message send_message = {0};
                send_message.len = RSA_public_encrypt(strlen(temp), temp, send_message.encypted_message, clients[i].rsa_pub_key, RSA_PKCS1_PADDING);
                send_struct(clients[i].sockfd, &send_message);
            }
        }
```

### Client
1. Định nghĩa struct `Encrypted_message` chứa thông tin của tin nhắn (tương tự ở server).

2. Khởi tạo `client_rsa_key` để mã hóa tin nhắn, lưu public key của client vào biến `client_pub_key` sau đó lưu public key của client dưới dạng xâu (để gửi cho server).

3. Nhận xâu public key của server từ server, lưu vào biến `server_pub_key` sau đó lưu public key của server vào biến `server_rsa_key`.
```c
int recv_len = recv(client_sockfd, buffer, sizeof(buffer), 0);
    char *server_pub_key = malloc(recv_len);
    strcpy(server_pub_key, buffer);
    printf("Public key recive from server: %s\n", server_pub_key);

    // read public key
    BIO *server_pub_keybio = BIO_new_mem_buf(server_pub_key, -1);
    if (server_pub_keybio == NULL)
    {
        printf("Failed to create public key BIO\n");
        return EXIT_FAILURE;
    }

    server_pub_rsa = PEM_read_bio_RSAPublicKey(server_pub_keybio, &server_pub_rsa, NULL, NULL);
    if (server_pub_rsa == NULL)
    {
        printf("Failed to create RSA key\n");
        return EXIT_FAILURE;
    }
```
4. Tạo 2 thread mới để xử lý việc gửi tin nhắn và nhận tin nhắn:
    - Thread xử lý việc gửi tin nhắn:
        - Nhập tên của client. Mã hóa tên đó bằng public key của server. Gửi tên đã mã hóa đến server (sử dụng struct `Encrypted_message`).
        - Nhập tin nhắn và mã hóa tin nhắn đó bằng public key của server.
        - Gửi tin nhắn đã mã hóa đến server.
        - Dùng vòng lặp while(1) để liên tục gửi tin nhắn đến server.
```c
void *send_message(void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char client_name[1024];
    Encrypted_message message;
    char input_message[1024];
    // enter name and check then send to server
    while (1)
    {
        printf("Enter your name: ");
        fgets(client_name, 1024, stdin);
        client_name[strlen(client_name) - 1] = '\0';
        if (strcmp(client_name, "") != 0)
            break;
    }
    message.len = RSA_public_encrypt(strlen(client_name), client_name, message.encypted_message, server_pub_rsa, RSA_PKCS1_PADDING);
    int bytes_sent = send_struct(socket, &message);
    printf("%d bytes sent\n", bytes_sent);
    while (1)
    {
        // printf("Enter message: ");
        fgets(input_message, 1024, stdin);
        input_message[strlen(input_message) - 1] = '\0';
        if (strcmp(input_message, "") != 0)
        {
            // clear buffer
            Encrypted_message message = {0};
            // write new buffer
            message.len = RSA_public_encrypt(strlen(input_message), input_message, message.encypted_message, server_pub_rsa, RSA_PKCS1_PADDING);
            send_struct(socket, &message);
        }
    }
}
```

    - Thread xử lý việc nhận tin nhắn:
        - Nhận tin nhắn từ server, giải mã tin nhắn đó bằng private key của client.
        - In tin nhắn ra màn hình.
        - Dùng vòng lặp while(1) để liên tục nhận tin nhắn từ server.

```c
void *recv_message(void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char dec_message[1024];
    int dec_message_len;
    while (1)
    {
        Encrypted_message received_message = {0};
        memset(dec_message, 0, 1024);
        int recv_len = recv_struct(socket, &received_message);
        if (recv_len < 0)
        {
            perror("recv");
            exit(1);
        }
        if (recv_len == 0)
        {
            printf("Server disconnected\n");
            exit(1);
        }
        dec_message_len = RSA_private_decrypt(received_message.len, received_message.encypted_message, dec_message, client_rsa_key, RSA_PKCS1_PADDING);
        printf("%s\n", dec_message);
    }
}
```