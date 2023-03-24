#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <assert.h>

#define SERVER_IP "127.0.0.1"
#define PORT "8080"
#define BUFFER_SIZE 1024

RSA *client_rsa_key;
char *client_pub_key;
int client_pub_key_len;

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

    client_rsa_key = RSA_new();
    ret = RSA_generate_key_ex(client_rsa_key, bits, bne, NULL);
    if (ret != 1)
    {
        printf("Create RSA key fail.\n");
        exit(EXIT_FAILURE);
    }

    assert(client_rsa_key != NULL);

    // get client public key - to send to server 
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, client_rsa_key);

    client_pub_key_len = BIO_get_mem_data(bio, &client_pub_key);
    client_pub_key[client_pub_key_len] = '\0';
    // printf("client public key: %s\n Length: %d\n", client_pub_key, client_pub_key_len);
    // get client private key - to decrypt message

}

void *send_message(void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char message[1024];

    // enter name and check then send to server
    while (1)
    {
        printf("Enter your name: ");
        fgets(message, 1024, stdin);
        message[strlen(message) - 1] = '\0';
        if (strcmp(message, "") != 0)
            break;
    }
    if (send(socket, message, strlen(message), 0) < 0)
    {
        perror("send");
        exit(1);
    }

    while (1)
    {
        // printf("Enter message: ");
        fgets(message, 1024, stdin);
        message[strlen(message) - 1] = '\0';
        if (strcmp(message, "") != 0)
        {
            if (send(socket, message, strlen(message), 0) < 0)
            {
                perror("send");
                exit(1);
            }
        }
    }
}

void *recv_message(void *client_sockfd)
{
    int socket = *(int *)client_sockfd;
    char message[1024];
    while (1)
    {
        int recv_len = recv(socket, message, 1024, 0);
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
        message[recv_len] = '\0';
        printf("%s\n", message);
    }
}

int main(int argc, char const *argv[])
{
    char buffer[BUFFER_SIZE];
    generate_key();

    printf("client public key: %s\n Length: %d\n", client_pub_key, client_pub_key_len);

    int client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);

    if (connect(client_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        exit(1);
    }

    printf("Connected to server\n");

    // send public key to server
    send(client_sockfd, client_pub_key, strlen(client_pub_key), 0);
    pritnf("Public key sent to server: %s\n", client_pub_key);

    // recv server's public key and store in server_pub_key
    int recv_len = recv(client_sockfd, buffer, sizeof(buffer), 0);
    char *server_pub_key = malloc(recv_len);
    strcpy(server_pub_key, buffer);
    pritnf("Public key recive from server: %s\n", server_pub_key);
    pthread_t send_thread, recv_thread;
    pthread_create(&send_thread, NULL, send_message, (void *)&client_sockfd);
    pthread_create(&recv_thread, NULL, recv_message, (void *)&client_sockfd);

    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);

    return 0;
}