#include <stdio.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <assert.h>
#include <string.h>

int encrypt_message(char *message, RSA *rsa, char *encrypted)
{
    int ret = -1;
    int message_len = strlen(message);
    int key_len = RSA_size(rsa);
    ret = RSA_public_encrypt(message_len, (unsigned char*) message, (unsigned char*) encrypted, rsa, RSA_PKCS1_PADDING);
    if (ret == -1)
    {
        printf("RSA_public_encrypt failed\n");
    }
    return ret;
}

int decrypt_message(char *message, int len, RSA *rsa, char *decrypted)
{
    int ret = RSA_private_decrypt(len, (unsigned char *)message, (unsigned char *)decrypted, rsa, RSA_PKCS1_PADDING);
    if (ret == -1)
    {
        printf("RSA_private_decrypt failed\n");
    }
    return ret;
}

int main(int argc, char *argv[])
{
    char server_pub_key[] = "-----BEGIN RSA PUBLIC KEY-----\n"
                            "MIGJAoGBAK1laUqG4LwnQOH8LUlUdWa2d8KNqL/f42YkE3fq2f6yQUefDVhz/cQC\n"
                            "VlU2HvPZajwtruxMEAmg9XWgYPZSVtnxgGwO1K56HoX8Q3uCtSRSqaWqRjyTUKFz\n"
                            "8KdxlfJj7W3Fm+OTX0p+kDGBDU3pGpboDPNER6c5Oq1ZYsRez0/hAgMBAAE=\n"
                            "-----END RSA PUBLIC KEY-----\n";

    char server_private_key[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                                "MIICXQIBAAKBgQCtZWlKhuC8J0Dh/C1JVHVmtnfCjai/3+NmJBN36tn+skFHnw1Y\n"
                                "c/3EAlZVNh7z2Wo8La7sTBAJoPV1oGD2UlbZ8YBsDtSueh6F/EN7grUkUqmlqkY8\n"
                                "k1Chc/CncZXyY+1txZvjk19KfpAxgQ1N6RqW6AzzREenOTqtWWLEXs9P4QIDAQAB\n"
                                "AoGAQbEjA943tHD2ruc4TQjXdbN5idbbcN4kq+TND2iFcG4eN0E18CX5pVHxXVUk\n"
                                "wuPC0MvJ8rIafVtiw06gjZHCXy1bILt2A1mh0rl7WbHcIdr6V6rkGHxsT3bHJ9tC\n"
                                "UIvI06hb2c6OfXF9z4qyijTQiZcQCDPpBqtfot97pk3BvvUCQQDldqTvGZiA7NRT\n"
                                "kqgFwG3WVG/+LzVMv9FjFXAEUzFnjkuuzoEfbDyVHDJ2DMu2OAtPPMdVtzDHh1zg\n"
                                "hOHnwuL3AkEAwXLfQTt5c/hVNi5oD4Lwa1wUgtxRADgU4JtjSJL7Z3vajYCJ3akB\n"
                                "ELE9jOnrUjtIp6IfQCOJTEfIiXYXPYvV5wJBANSZCFc/L7zDsDV+O46YqytZMCoh\n"
                                "MxDY5/cVdaOMMMnxXM2pJpkmfzrn1Rjq4hMB+fiAJ2+TOu6iy7p5Y5SHTCECQQCg\n"
                                "0G7Z2qhHiQzFYuSs6GwWw9BlTOOla/mnEmYBwfZu+54e/dkeRM2W49DIIPm4PYJT\n"
                                "oMmb1y7fE9mYtGvzhRjHAkB2Q9OXJE28JEAMVBFvCB3iee+w5XppjizpKC4wAsWn\n"
                                "QufomM28QZ6HCd8CxisSaUA/5GE3VgNyUaYRsrB8CLbU\n"
                                "-----END RSA PRIVATE KEY-----\n";

    RSA *server_pub_rsa = NULL;

    // read public key
    BIO *server_pub_key_bio = BIO_new_mem_buf(server_pub_key, -1); 
    if (server_pub_key_bio == NULL)
    {
        printf("Failed to create key BIO");
        return EXIT_FAILURE;
    }

    server_pub_rsa = PEM_read_bio_RSAPublicKey(server_pub_key_bio, &server_pub_rsa, NULL, NULL);
    if (server_pub_rsa == NULL)
    {
        printf("Failed to create RSA");
        return EXIT_FAILURE;
    }

// read private key 
    BIO *server_pri_keybio = BIO_new_mem_buf(server_private_key, -1);
    if (server_pri_keybio == NULL)
    {
        printf("Failed to create private key BIO");
        return EXIT_FAILURE;
    }

    RSA *server_pri_rsa = NULL;
    server_pri_rsa = PEM_read_bio_RSAPrivateKey(server_pri_keybio, &server_pri_rsa, NULL, NULL);
    if (server_pri_rsa == NULL)
    {
        printf("Failed to create RSA");
        return EXIT_FAILURE;
    }

    // message to encrypt
    char *msg = "hello, world!";
    printf("Message to encrypt: %s\n", msg);
    
    //encrypt message
    int enc_msg_size = 0;
    char enc_msg[1024] = {0};
    // printf("size of encrypted: %ld\n", sizeof(enc_msg));

    enc_msg_size = RSA_public_encrypt(strlen(msg), msg, enc_msg, server_pub_rsa, RSA_PKCS1_PADDING);
    printf("Encrypt message: \n%s \n", enc_msg);
    printf("Encrypted message size: %d\n", enc_msg_size);

    //decrypt message
    char dec_msg[1024];
    int dec_msg_size = 0;
    dec_msg_size = RSA_private_decrypt(enc_msg_size, enc_msg, dec_msg, server_pri_rsa, RSA_PKCS1_PADDING);
    printf("Decrypt message: %s\n", dec_msg);
    printf("Decrypt message size: %d\n", dec_msg_size);
    // RSA_free(client_rsa_key);
    return 0;
}