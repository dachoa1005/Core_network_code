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
#include <assert.h>

#define PORT 8080
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024


RSA *server_rsa_key;
char *server_pub_key;
int server_pub_key_len;

void generate_key()
{
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

    assert(server_rsa_key != NULL);

    // get client public key - to send to server 
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, server_rsa_key);

    server_pub_key_len = BIO_get_mem_data(bio, &server_pub_key);
    server_pub_key[server_pub_key_len] = '\0';
    // printf("client public key: %s\n Length: %d\n", server_pub_key, server_pub_key_len);
    // get client private key - to decrypt message

}

typedef struct
{
    int sockfd;
    char *name;
    RSA *rsa_pub_key;
} Client;

Client clients[MAX_CLIENTS];
int client_number = 0;

char *encrypt_message(char *message, RSA *rsa)
{
    int len = RSA_size(rsa);
    char *encrypted = malloc(len + 1);
    int ret = RSA_public_encrypt(strlen(message), (unsigned char *)message, (unsigned char *)encrypted, rsa, RSA_PKCS1_PADDING);
    if (ret == -1 || strcmp(encrypted,"")==0)
    {
        printf("RSA_public_encrypt failed\n");
        return NULL;
    }
    return encrypted;
}

char *decrypt_message(char *message, RSA *rsa)
{
    int len = RSA_size(rsa);
    char *decrypted = malloc(len + 1);
    int ret = RSA_private_decrypt(len, (unsigned char *)message, (unsigned char *)decrypted, rsa, RSA_PKCS1_PADDING);
    if (ret == -1 || strcmp(decrypted,"")==0)
    {
        printf("RSA_private_decrypt failed\n");
        return NULL;
    }
    return decrypted;
}

void *connection_handle (void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char buffer[BUFFER_SIZE];
    char *client_name;
    int read_len;
    RSA *rsa;
    char *enc_message;
    char *dec_message;

    // recive client public key, send server public key
    for (int i=0 ; i < client_number; i++)
    {
        if (clients[i].sockfd == socket)
        {
            recv(socket, buffer, BUFFER_SIZE, 0);
            // clients[i].
            printf("Client public key: %s\n", buffer);
    
            send(socket, server_pub_key, server_pub_key_len, 0);
            printf("Public key send to client: %s\n", server_pub_key);
            continue;
        }
    }

    // recive client name
    memset(buffer, sizeof(buffer), 0);
    read_len = recv(socket, buffer, BUFFER_SIZE, 0);
    buffer[read_len] = '\0';
    dec_message = decrypt_message(buffer, server_rsa_key);
    printf("Client name: \n%s\n", buffer);
    

}

int main(int argc, char const *argv[])
{
    //generate server key
    generate_key();
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
        printf("Waiting for new connection...\n");
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
