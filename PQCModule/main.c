#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "PQCModule.h"

#define PLAINTEXT "Hello, this is a test message!"
#define PLAINTEXT_LEN strlen(PLAINTEXT)

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Initialize the PQC module
    if (PQCModule_Init() != 0) {
        fprintf(stderr, "Failed to initialize PQC module.\n");
        return EXIT_FAILURE;
    }

    // Generate key pair
    uint8_t *public_key = NULL;
    size_t public_key_len = 0;
    uint8_t *secret_key = NULL;
    size_t secret_key_len = 0;

    if (PQCModule_GenerateKeyPair(&public_key, &public_key_len, &secret_key, &secret_key_len) != 0 || 
        public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "Failed to generate key pair.\n");
        PQCModule_Cleanup();
        return EXIT_FAILURE;
    }

    // Print public key in hex format
    printf("Public key: ");
    print_hex(public_key, public_key_len);

    // Encrypt the plaintext
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    if (PQCModule_Encrypt(public_key, public_key_len, (uint8_t *)PLAINTEXT, PLAINTEXT_LEN, &ciphertext, &ciphertext_len) != 0) {
        fprintf(stderr, "Failed to encrypt the plaintext.\n");
        free(public_key);
        free(secret_key);
        PQCModule_Cleanup();
        return EXIT_FAILURE;
    }

    printf("Encrypted message length: %zu bytes\n", ciphertext_len);
    printf("Ciphertext: ");
    print_hex(ciphertext, ciphertext_len);

    // Decrypt the ciphertext
    uint8_t *decrypted_plaintext = NULL;
    size_t decrypted_plaintext_len = 0;

    if (PQCModule_Decrypt(secret_key, secret_key_len, ciphertext, ciphertext_len, &decrypted_plaintext, &decrypted_plaintext_len) != 0) {
        fprintf(stderr, "Failed to decrypt the ciphertext.\n");
        free(public_key);
        free(secret_key);
        free(ciphertext);
        PQCModule_Cleanup();
        return EXIT_FAILURE;
    }

    // Print the decrypted plaintext
    printf("Decrypted message: %.*s\n", (int)decrypted_plaintext_len, decrypted_plaintext);

    // Cleanup
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(decrypted_plaintext);
    PQCModule_Cleanup();

    return EXIT_SUCCESS;
}
