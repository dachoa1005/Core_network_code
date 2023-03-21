#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8889
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024
typedef struct
{
    SSL *ssl;
    int socket;
    char *name;
} Client;

Client clients[MAX_CLIENTS];
int client_num = 0;

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

void *connection_handle(void *ssl)
{
    SSL *client_ssl = (SSL *)ssl;
    char *client_name;
    char buffer[BUFFER_SIZE];
    int read_len;

    // get client name
    SSL_read(ssl, buffer, sizeof(buffer));
    for (int i = 0; i < client_num; i++)
    {
        if (clients[i].ssl == client_ssl)
        {
            clients[i].name = malloc(strlen(buffer) + 1);
            strcpy(clients[i].name, buffer);
            client_name = malloc(strlen(buffer) + 1);
            strcpy(client_name, buffer);
            break;
        }
    }

    if (strcmp(client_name, "")!= 0)
        printf("%s has joined the chat\n", client_name);

    // recive from client and send to all other clients
    do
    {
        read_len = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[read_len] = '\0';

        if (read_len > 0)
        {
            // add client name to message
            char message[BUFFER_SIZE];
            strcpy(message, client_name);
            strcat(message, ": ");
            strcat(message, buffer);

            // send message to all clients
            for (int i = 0; i < client_num; i++)
            {
                if (clients[i].ssl != ssl && clients[i].ssl != NULL && clients[i].name != NULL)
                {
                    SSL_write(clients[i].ssl, message, strlen(message));
                }
            }
        }
        else
        {
            // client disconnected
            for (int i = 0; i < client_num; i++)
            {
                if (clients[i].ssl == ssl)
                {
                    printf("Client %s has socketfd: %d has disconnected\n",clients[i].name, clients[i].socket);
                    // if (strcmp(clients[i].name, "")!= 0)
                    // printf("%s has left the chat\n", clients[i].name);
                    clients[i].ssl = NULL;
                    clients[i].socket = -1;
                    free(clients[i].name);
                    clients[i].name = NULL;
                    break;
                }
            }
        }
    } while (read_len > 0);
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    int bytes;
    char buffer[1024];
    int client_sockfd, server_sockfd;
    struct sockaddr_in server_addr;
    int addrlen = sizeof(server_addr);
    pthread_t threads[MAX_CLIENTS];
    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_sockfd, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    // init clients array
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        clients[i].socket = -1;
        clients[i].ssl = NULL;
        clients[i].name = NULL;
    }

    /* Handle connections */
    while (1)
    {
        client_sockfd = accept(server_sockfd, (struct sockaddr *)&server_addr, (socklen_t *)&addrlen);
        if (client_sockfd < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        SSL *ssl;
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sockfd);
        // BIO *bio = BIO_new_socket(client_sockfd, BIO_NOCLOSE);
        // SSL_set_bio(ssl, bio, bio);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            continue;
        }
        // SSL_read(ssl, buf, sizeof(buf));
        // printf("Received: %s", buf);

        // add to clients array
        clients[client_num].socket = client_sockfd;
        clients[client_num].ssl = ssl;

        printf("Client has socketfd: %d has connected. \n", client_sockfd);

        // create thread to handle each client
        pthread_create(&threads[client_num], NULL, connection_handle, (void *)ssl);

        // join thread
        // for (int i = 0; i < client_num; i++)
        // {
        //     pthread_join(threads[client_num], NULL);
        // }
        client_num += 1;

    }
    close(server_sockfd);
    SSL_CTX_free(ctx);
}
