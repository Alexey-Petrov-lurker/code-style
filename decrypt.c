// gcc -Wall -g -o decrypt decrypt.c -lssl -lcrypto
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

static int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); /* Create and initialise the context */

    if (!ctx) handleErrors();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) handleErrors();

    int len;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();

    int pad_len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &pad_len)) handleErrors();

    EVP_CIPHER_CTX_free(ctx); /* Clean up */

    return len + pad_len;
}

int main(int argc, char *argv[]) {

        if ( argc != 2 ) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(0);
    }
    const unsigned char key_s[] = "key";
    const unsigned char iv_s[] = "iv";

    unsigned char key[key_l], iv[iv_l];

    MD5(iv_s, strlen((const char *)iv_s), iv); /* 128 bit IV Should be hardcoded in both encrypt and decrypt */
    SHA256(key_s, strlen((const char *)key_s), key); /* 256 bit key */

    unsigned char base64_in[iv_l], base64_out[iv_l];

    unsigned char decryptedtext[iv_l]; /* Buffer for the decrypted text */

    CONF_modules_load_file(NULL, NULL, 0); /* Initialise the library */

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        printf("cannot open %s\n", argv[1]);
        exit(1);
    }
    fgets((char *)base64_in, iv_l, f);
    fclose(f);

    /* Decrypt the plaintext */
    const int ciphertext_len = strlen((const char *)base64_in);
    printf("%d %s\n", ciphertext_len, base64_in);

    const int length = EVP_DecodeBlock(base64_out, base64_in, ciphertext_len);

    int i;
    for (i = ciphertext_len - 1; base64_in[i] == '='; --i);

    const int len = length - (ciphertext_len - i + 1);
    printf("%d %s\n", len, base64_out);

    BIO_dump_fp(stdout, (const char *)base64_out, len);

    const int decryptedtext_len = decrypt(base64_out, len, key, iv, decryptedtext);

    decryptedtext[decryptedtext_len] = '\0'; /* Add a NULL terminator. We are expecting printable text */

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%d %s\n", decryptedtext_len, decryptedtext);

    EVP_cleanup(); /* Clean up */
    ERR_free_strings();

    return 0;
}
