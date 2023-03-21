# Encrypt Chat Group
1. Make 
2. `./server` - để chạy server
3. Mở thêm n terminal khác, mỗi terminal chạy `./client`

## Khởi tạo key và certificate
1. Tạo khóa riêng tư (private key):
```console
openssl genrsa -out key.pem 2048
```
Lệnh này sẽ khởi tạo khóa riêng tư RSA 2048 bit và lưu vào file `key.pem`.\
2. Tạo yêu cầu chứng chỉ (certificate signing request - CSR):
```console
openssl req -new -key key.pem -out csr.pem
``` 
Sau khi tạo private key, ta sẽ cần tạo yêu cầu chứng chỉ CSR để yêu cầu cơ quan chứng nhận SSL phát hành chứng chỉ SSL cho mình.\
Lệnh này sẽ yêu cầu chứng chỉ RSA và lưu nó vào file csr.pem.\
3. Kết hợp khóa và chứng chỉ:
```console 
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem
```
Lệnh này dùng để tạo 1 chứng chỉ (certificate) từ CSR và private key được tạo ở trên và lưu vào file cert.pem

## Giải thích code
1. Server
    - Khởi tạo 1 context mới với method là TLS_server_method
```C
SSL_CTX *ctx;
ctx = create_context();
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
```
    
    - Config context để thiết lập chứng chỉ và private key cho server
```C
ctx = create_context();
configure_context(ctx);
/*___________________________________*/
void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
```
    - Định nghĩa 1 struct để lưu thông tin client kết nối đến bao gồm ssl, socketfd và name-tên client
    - Tạo 1 mảng clients để lưu trữ thông tin các client.
    - Init mảng clients với mỗi client có ssl = NULL, socket = -1 và name = NULL
    - Dùng vòng lặp while (1) để server luôn listen trên port 8888