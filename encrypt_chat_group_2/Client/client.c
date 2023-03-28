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
#define PORT 8889
#define BUFFER_SIZE 1024

RSA *client_rsa_key;
char *client_pub_key;
int client_pub_key_len;
RSA *server_pub_rsa = NULL; // use for encrpyt message to send to server

typedef struct
{
    int len;
    char encypted_message[1024];
} Encrypted_message;

int send_struct(int sockfd, Encrypted_message *message_to_send)
{
    char *buffer = (char *)message_to_send;
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

int recv_struct(int sockfd, Encrypted_message *message_to_recv)
{
    char *buffer = (char *)message_to_recv;
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
    BN_free(bne);
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
    // printf("Encrypted message: \n");
    // for (int i = 0; i < message.len; i++)
    // {
    //     printf("%02x", (unsigned char)message.encypted_message[i]);
    // }
    // printf("\n");
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
            // printf("Encrypted message: \n");
            // for (int i = 0; i < message.len; i++)
            // {
            //     printf("%02x", (unsigned char)message.encypted_message[i]);
            // }
            // printf("\n");
        }
    }
}

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
        // printf("Encrypted message: \n");
        // for (int i = 0; i < received_message.len; i++)
        // {
        //     printf("%02x", (unsigned char)received_message.encypted_message[i]);
        // }
        // printf("\n");
        dec_message_len = RSA_private_decrypt(received_message.len, received_message.encypted_message, dec_message, client_rsa_key, RSA_PKCS1_PADDING);
        printf("%s\n", dec_message);
    }
}

int main(int argc, char const *argv[])
{
    char buffer[BUFFER_SIZE];
    generate_key();

    // printf("client public key: %s\n Length: %d\n", client_pub_key, client_pub_key_len);

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
    printf("Public key sent to server: %s\n", client_pub_key);

    // recv server's public key and store in server_pub_key
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

    pthread_t send_thread, recv_thread;
    pthread_create(&send_thread, NULL, send_message, (void *)&client_sockfd);
    pthread_create(&recv_thread, NULL, recv_message, (void *)&client_sockfd);

    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);

    return 0;
}
