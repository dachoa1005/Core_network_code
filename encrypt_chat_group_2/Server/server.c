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

#define PORT 8889
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

RSA *server_rsa_key = NULL;
char *server_pub_key = NULL;
char *server_pri_key = NULL;
int server_pub_key_len = 0;
int server_pri_key_len = 0;

typedef struct
{
    int sockfd;
    char *name;
    RSA *rsa_pub_key;
} Client;

typedef struct
{
    int len;
    char encypted_message[1024];
} Encrypted_message;

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

    // get server public key - to send to server
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, server_rsa_key);

    server_pub_key_len = BIO_get_mem_data(bio, &server_pub_key);
    server_pub_key[server_pub_key_len] = '\0';
    printf("server public key: %s\n Length: %d\n", server_pub_key, server_pub_key_len);
    // get server private key - to decrypt message

    // get server private key - to decrypt message
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, server_rsa_key, NULL, NULL, 0, NULL, NULL);

    server_pri_key_len = BIO_get_mem_data(bio, &server_pri_key);
    server_pri_key[server_pri_key_len] = '\0';
    printf("server private key: %s\n Length: %d\n", server_pri_key, server_pri_key_len);
}

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

Client clients[MAX_CLIENTS];
int client_number = 0;

void *connection_handle(void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char buffer[BUFFER_SIZE];
    char dec_message[BUFFER_SIZE];
    char *client_name;
    int read_len;
    int len;
    Encrypted_message message;
    int dec_message_len = 0;
    int bytes_recv;
    char temp[BUFFER_SIZE];

    // recive client name

    bytes_recv = recv_struct(socket, &message);
    printf("%d bytes recv\n", bytes_recv);

    // printf("Recv encrypted message: \n");
    // for (int i = 0; i < message.len; i++)
    // {
    //     printf("%02x", (unsigned char)message.encypted_message[i]);
    // }
    // printf("\n");

    dec_message_len = RSA_private_decrypt(message.len, message.encypted_message, dec_message, server_rsa_key, RSA_PKCS1_PADDING);
    printf("Client name: %s\n", dec_message);
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

    printf("Client %s has joined the chat room.\n", client_name);

    do
    {
        Encrypted_message recv_message = {0};
        read_len = recv_struct(socket, &recv_message);

        if (read_len > 0)
        {
            memset(dec_message, 0, sizeof(dec_message));
            memset(temp, 0, sizeof(temp));

            dec_message_len = RSA_private_decrypt(recv_message.len, recv_message.encypted_message, dec_message, server_rsa_key, RSA_PKCS1_PADDING);
            strcpy(temp, client_name);
            strcat(temp, ": ");
            strcat(temp, dec_message);
            printf("%s\n", temp);

            // encrypt message then send to all other client
            for (int i = 0; i < MAX_CLIENTS; i++)
            {
                if (clients[i].sockfd != socket && clients[i].sockfd != -1)
                {
                    Encrypted_message send_message = {0};
                    send_message.len = RSA_public_encrypt(strlen(temp), temp, send_message.encypted_message, clients[i].rsa_pub_key, RSA_PKCS1_PADDING);
                    send_struct(clients[i].sockfd, &send_message);
                    // printf("Encrypted message: \n");
                    // for (int i = 0; i < send_message.len; i++)
                    // {
                    //     printf("%02x", (unsigned char)send_message.encypted_message[i]);
                    // }
                    // printf("\n");
                }
            }
        }
        else if (read_len == 0)
        {
            printf("Client %s has left the chat room.\n", client_name);
            // remove client from clients array
            for (int i = 0; i < MAX_CLIENTS; i++)
            {
                if (clients[i].sockfd == socket)
                {
                    clients[i].sockfd = -1;
                    clients[i].rsa_pub_key = NULL;
                    clients[i].name = NULL;
                    break;
                }
            }
        }
    } while (read_len > 0);

    return 0;
}

int main(int argc, char const *argv[])
{
    // generate server key
    generate_key();
    // init clients array
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        clients[i].sockfd = -1;
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

    // create server socket
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
        client_number++;
        printf("Client has socketfd: %d has connected.\n\n", client_sockfd);

        // recive client public key, send server public key
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].sockfd == client_sockfd)
            {
                // recive client public key
                recv(client_sockfd, buffer, BUFFER_SIZE, 0);
                // create rsa from client public key
                BIO *bio = BIO_new_mem_buf(buffer, -1);
                RSA *client_rsa_pub_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
                clients[i].rsa_pub_key = client_rsa_pub_key;

                // send server public key
                send(client_sockfd, server_pub_key, server_pub_key_len, 0);
                // printf("Public key send to client: %s\n", server_pub_key);
            }
        }

        // create thread to handle each client
        if (pthread_create(&threads[client_number], NULL, connection_handle, (void *)&client_sockfd) != 0)
        {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
