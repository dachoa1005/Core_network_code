#include <stdio.h>
#include <netdb.h>

int main() {
    int protocol_number = 6; // TCP protocol number
    struct protoent *protocol = getprotobynumber(protocol_number);
    
    if (protocol == NULL) {
        printf("Error: Unknown protocol number\n");
        return 1;
    }
    
    printf("Protocol name for number %d is %s\n", protocol_number, protocol->p_name);
    
    return 0;
}
