// gcc -Wall -g -o encrypt encrypt.c -lssl -lcrypto
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
// Openssl
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

static const int key_l = 256;
static const int iv_l = 128;

static void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(-1);
}

static int encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); /* Create and initialise the context */

    if (!ctx) handleErrors();

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) handleErrors();

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();

    int pad_len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &pad_len)) handleErrors();

    EVP_CIPHER_CTX_free(ctx); /* Clean up */

    return len + pad_len;
}

int main (int argc, char *argv[]) {

    if ( argc != 2 ) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(0);
    }
    const unsigned char key_s[] = "key";
    const unsigned char iv_s[] = "iv";

    unsigned char key[key_l], iv[iv_l];

    MD5(iv_s, strlen((const char *)iv_s), iv); /* 128 bit IV  Should be hardcoded in both encrypt and decrypt. */
    SHA256(key_s, strlen((const char *)key_s), key); /* 256 bit key */

    const unsigned char plaintext[] = "This is a Test!"; /* Message to be encrypted */

    unsigned char ciphertext[iv_l], base64[iv_l];

    CONF_modules_load_file(NULL, NULL, 0); /* Initialise the library */

    const int ciphertext_len = encrypt(plaintext, strlen((const char *)plaintext), key, iv, ciphertext); /* Encrypt the plaintext */

    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    printf("%d %s\n", ciphertext_len, ciphertext);

    const int encode_str_size = EVP_EncodeBlock(base64, ciphertext, ciphertext_len);
    printf("%d %s\n", encode_str_size, base64);

    FILE *f = fopen(argv[1], "w");
    if (!f) {
        printf("cannot open %s\n", argv[1]);        
        exit(1);
    }
    fprintf(f, "%s\n", base64);
    fclose(f);

    EVP_cleanup(); /* Clean up */
    ERR_free_strings();

    return 0;
}
