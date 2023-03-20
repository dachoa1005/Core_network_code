#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void *send_message(void *ssl)
{
    SSL *client_ssl = (SSL *)ssl;
    char message[1024];
    int bytes;
    
    // enter client name
    // while (1)
    // {
    //     printf("Enter your name: \n");
    //     fgets(message, 1024, stdin);
    //     message[strlen(message) - 1] = '\0';
    //     if (strcmp(message, "") != 0)
    //         break;
    // }
    // printf("%s\n", message);
    // SSL_write(client_ssl, message, strlen(message));

    // send message to server 
    while (1)
    {
        // fgets(message, 1024, stdin);
        scanf("%[^\n]%*c", message);
        message[strlen(message) - 1] = '\0';
        if (strcmp(message, "") != 0)
            bytes = SSL_write(client_ssl, message, strlen(message));
        if (bytes <= 0)
        {
            perror("Unable to send message");
            exit(EXIT_FAILURE);
        }
    }
}

void *recv_message(void *ssl)
{
    SSL *client_ssl = (SSL *)ssl;
    char message[1024];
    int bytes;
    while (1)
    {
        bytes = SSL_read(client_ssl, message, sizeof(message));
        if (bytes == 0)
        {
            printf("Server disconnected\n");
            exit(EXIT_FAILURE);
        }
        else if (bytes < 0)
        {
            perror("Unable to receive message");
            exit(EXIT_FAILURE);
        }

        message[bytes] = '\0';
        printf("%s\n", message);
    }
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    int client_sockfd;
    char buffer[1024];
    pthread_t send_thread, recv_thread;


    if (argc != 2)
    {
        printf("Usage: %s <IP Address>\n", argv[0]);
        return 1;
    }

    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd < 0)
    {
        perror("Unable to create socket");
        return 1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(4433);

    if (connect(client_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Unable to connect");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sockfd);
    if (SSL_connect(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    // for (int i = 0; i < 10; i++)
    // {
    //     SSL_write(ssl, "Hello, server!", strlen("Hello, server!"));
    //     printf("Sent: Hello, server!\n");
    //     int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    //     buffer[bytes] = 0;
    //     printf("Received: %s\n", buffer);
    // }

    pthread_create(&send_thread, NULL, send_message, (void *)ssl);
    pthread_create(&recv_thread, NULL, recv_message, (void *)ssl);
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
