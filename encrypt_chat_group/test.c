#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char const *argv[])
{
    char message[1024];
    printf("Enter message: ");
    gets(message);
    // message[strlen(message) - 1] = '\0';
    printf("Message: %s\n", message);
    return 0;
}
