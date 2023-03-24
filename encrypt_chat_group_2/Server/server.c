#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

#define PORT 8080
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

typedef struct
{
    int sockfd;
    char *name;
    RSA *rsa_pub_key;
} Client;

Client clients[MAX_CLIENTS];
int client_number = 0;

void *connection_handle (void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char buffer[BUFFER_SIZE];
    char *client_name;
    int read_len;
    RSA *rsa;

    // recive client public key
    for (int i=0 ; i < client_number; i++)
    {
        if (clients[i].sockfd == client_sockfd)
        {
            
        }
    }
}

int main(int argc, char const *argv[])
{
    // init clients array
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        clients[i].sockfd = 0;
        clients[i].rsa_pub_key = NULL;
        clients[i].name = NULL;
    }

    // init socket
    int server_sockfd, client_sockfd;
    struct sockaddr_in server_address, client_address;
    int ser_addr_len = sizeof(server_address);
    int cli_addr_len = sizeof(client_address);
    char buffer[BUFFER_SIZE];
    pthread_t threads[MAX_CLIENTS];

    //create server socket
    if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    printf("Server socket created.\n");

    // set socket
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    // bind socket
    if (bind(server_sockfd, (struct sockaddr *)&server_address, ser_addr_len) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket bind to port %d successfully.\n", PORT);

    // listen 
    if (listen(server_sockfd, MAX_CLIENTS) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        pritnf("Waiting for new connection...\n");
        // accept connection
        client_sockfd = accept(server_sockfd, (struct sockaddr *)&server_address, (socklen_t *)&ser_addr_len);
        if (client_sockfd < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        clients[client_number].sockfd = client_sockfd;
        client_number += 1;
        printf("Client has socketfd: %d has connected.\n\n", client_sockfd);

        //create thread to handle each client
        if (pthread_create(&threads[client_number], NULL, connection_handle, (void *)&client_sockfd)!=0)
        {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

    }


    return 0;
}
