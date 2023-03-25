#include <stdio.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <assert.h>
#include <string.h>

RSA *client_rsa_key;

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
}


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

char *decrypt_message(char *message, RSA *rsa)
{
    int len = RSA_size(rsa);
    char *decrypted = malloc(len + 1);
    int ret = RSA_private_decrypt(len, (unsigned char *)message, (unsigned char *)decrypted, rsa, RSA_PKCS1_PADDING);
    if (ret == -1)
    {
        printf("RSA_private_decrypt failed\n");
        return NULL;
    }
    decrypted[ret] = '\0'; // Đảm bảo kết thúc chuỗi giải mã bằng ký tự '\0'
    return decrypted;
}
int main(int argc, char *argv[])
{
    // message to encrypt
    char *msg = "Hello, world!";
    printf("Message to encrypt: %s\n", msg);

    generate_key();

    char *enc_msg = encrypt_message(msg, client_rsa_key);
    printf("Encrypt message: \n%s\n", enc_msg);
    printf("\n");

    char *dec_msg = decrypt_message(enc_msg, client_rsa_key);
    printf("Decrypt message: %s\n", dec_msg);
    printf("\n");

    free(enc_msg);
    free(dec_msg);

    RSA_free(client_rsa_key);

    return 0;
}
