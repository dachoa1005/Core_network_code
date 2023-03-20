#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    char buffer[1024];
    struct sockaddr_in serv_addr;

    if (argc != 2) {
        printf("Usage: %s <IP Address>\n", argv[0]);
        return 1;
    }

    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        return 1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(4433);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Unable to connect");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_write(ssl, "Hello, Server!", strlen("Hello, Server!"));

    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = 0;
    printf("Received: %s", buffer);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
