#include <stdio.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <assert.h>
#include <string.h>


// bool generate_key()
// {
//     int bits = 1024;
//     int ret = 0;
//     BIGNUM *bne = NULL;
//     BIO *bp_public = NULL, *bp_private = NULL;

//     unsigned long e = RSA_F4;

//     // 1. generate rsa key
//     bne = BN_new();
//     ret = BN_set_word(bne, e);
//     if (ret != 1)
//     {
//         goto free_all;
//     }

//     rsa = RSA_new();
//     ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
//     if (ret != 1)
//     {
//         goto free_all;
//     }

//     // 2. save public key
//     bp_public = BIO_new_file("public.pem", "w+");
//     ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
//     if (ret != 1)
//     {
//         goto free_all;
//     }

//     // 3. save private key
//     bp_private = BIO_new_file("private.pem", "w+");
//     ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
//     if (ret != 1)
//     {
//         goto free_all;
//     }

//     // 4. free
// free_all:
//     BIO_free_all(bp_public);
//     BIO_free_all(bp_private);
//     RSA_free(rsa);
//     BN_free(bne);

//     return (ret == 1);
// }



int main(int argc, char *argv[])
{
    int bits = 1024;
    int ret = 0;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;
    RSA *rsa = NULL;

    unsigned long e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        goto free_all;
    }

    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
    if (ret != 1)
    {
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
    if (ret != 1)
    {
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
    if (ret != 1)
    {
        goto free_all;
    }

    // message to encrypt
    const char *msg = "hello";
    // size_t msglen = strlen(msg);

    // encrypt message
    char *enc_msg = NULL;
    enc_msg = malloc(RSA_size(rsa));
    printf("%s\n", msg);
    printf("Size of enc_msg: %ld\n", sizeof(enc_msg));
    int result = RSA_public_encrypt(strlen(msg)+1, (unsigned char *)msg, enc_msg, rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        return EXIT_FAILURE;
    }

    int enc_len = result;
    printf("Encrypt message: %s\n", enc_msg);
    printf("\n");


    //decrypt message
    char *dec_msg = NULL;
    dec_msg = malloc(RSA_size(rsa));
    result = RSA_private_decrypt(RSA_size(rsa), enc_msg, dec_msg, rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        return EXIT_FAILURE;
    }

    int dec_len = result;
    printf("Decrypt message: %s\n", dec_msg);
    printf("\n");
        // 4. free
free_all:
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(rsa);
    BN_free(bne);
    return 0;
}