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

int main(int argc, char const *argv[])
{
    char *buffer = "hello \0 world\0";

    printf("buffer: %s\n", buffer);
    printf("buffer length: %ld\n", strlen(buffer));
    printf("buffer size: %ld\n", sizeof(buffer));

    return 0;
}
