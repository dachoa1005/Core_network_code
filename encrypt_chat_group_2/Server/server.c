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
    if (ret == -1)
    {
        printf("RSA_public_encrypt failed\n");
        return NULL;
    }
    return encrypted;
}

char *decrypt_message(char *message, int message_len, RSA *rsa)
{
    int len = RSA_size(rsa);
    char *decrypted = (char *)malloc(len + 1);
    memset(decrypted, 0, len + 1);

    int ret = RSA_private_decrypt(message_len, (unsigned char *)message, (unsigned char *)decrypted, rsa, RSA_PKCS1_PADDING);
    if (ret == -1)
    {
        printf("RSA_private_decrypt failed\n");
        return NULL;
    }

    // Đảm bảo kết thúc chuỗi giải mã bằng ký tự '\0'
    decrypted[ret] = '\0';

    return decrypted;
}

void *connection_handle(void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char buffer[BUFFER_SIZE];
    char *client_name;
    int read_len;
    RSA *rsa;
    char *enc_message;
    char *dec_message;
    int len;
    // recive client public key, send server public key
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i].sockfd == socket)
        {
            // recive client public key
            recv(socket, buffer, BUFFER_SIZE, 0);
            // create rsa from client public key
            BIO *bio = BIO_new_mem_buf(buffer, -1);
            RSA *client_rsa_pub_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
            clients[i].rsa_pub_key = client_rsa_pub_key;

            // send server public key
            send(socket, server_pub_key, server_pub_key_len, 0);
            // printf("Public key send to client: %s\n", server_pub_key);
            continue;
        }
    }

    // recive client name
    memset(buffer, sizeof(buffer), 0);
    read_len = recv(socket, buffer, BUFFER_SIZE, 0);
    // Tính độ dài của buffer nhận được
    // int len = 0;
    while (len < read_len && buffer[len] != '\0') {
        len++;
    }
    // buffer[read_len] = '\0';
    dec_message = decrypt_message(buffer, RSA_size(server_rsa_key), server_rsa_key);
    printf("Client name: %s\n", dec_message);
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i].sockfd == socket)
        {
            clients[i].name = malloc(strlen(dec_message) + 1);
            strcpy(clients[i].name, dec_message);
            client_name = malloc(strlen(dec_message) + 1);
            strcpy(client_name, dec_message);
            continue;
        }
    }

    printf("Client %s has joined the chat room.\n", client_name);

    do
    {
        memset(buffer, sizeof(buffer), 0);
        read_len = recv(socket, buffer, BUFFER_SIZE, 0);
        buffer[read_len] = '\0';

        if (read_len > 0)
        {
            dec_message = decrypt_message(buffer, read_len, server_rsa_key);
            char temp[BUFFER_SIZE];
            strcpy(temp, client_name);
            strcat(temp, ": ");
            strcat(temp, dec_message);
            printf("%s\n", temp);

            // send to all other client
            for (int i = 0; i < MAX_CLIENTS; i++)
            {
                if (clients[i].sockfd != socket && clients[i].sockfd != -1)
                {
                    enc_message = encrypt_message(temp, clients[i].rsa_pub_key);
                    send(clients[i].sockfd, enc_message, strlen(enc_message), 0);
                }
            }
        }
        else 
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

        // create thread to handle each client
        if (pthread_create(&threads[client_number], NULL, connection_handle, (void *)&client_sockfd) != 0)
        {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
