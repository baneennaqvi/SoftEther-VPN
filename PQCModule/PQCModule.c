#include "PQCModule.h"
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>


static OQS_KEM *kem = NULL;

// Initialize the PQC algorithm (e.g., Kyber512)
int PQCModule_Init() {
    kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return -1; // Initialization failed
    }
    return 0; // Success
}

// Cleanup the PQC module
void PQCModule_Cleanup() {
    if (kem != NULL) {
        OQS_KEM_free(kem);
        kem = NULL;
    }
}

// Generate PQC key pair
int PQCModule_GenerateKeyPair(uint8_t **public_key, size_t *public_key_len,
                              uint8_t **secret_key, size_t *secret_key_len) {
    if (kem == NULL) return -1;

    *public_key = malloc(kem->length_public_key);
    *secret_key = malloc(kem->length_secret_key);
    if (*public_key == NULL || *secret_key == NULL) return -1;

    if (OQS_KEM_keypair(kem, *public_key, *secret_key) != OQS_SUCCESS) {
        free(*public_key);
        free(*secret_key);
        return -1;
    }

    *public_key_len = kem->length_public_key;
    *secret_key_len = kem->length_secret_key;

    return 0;
}

// Simple XOR encryption for demonstration
void simple_xor_encrypt(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output) {
    for (size_t i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
}

// Encrypt data using PQC
int PQCModule_Encrypt(uint8_t *public_key, size_t public_key_len,
                      uint8_t *plaintext, size_t plaintext_len,
                      uint8_t **ciphertext, size_t *ciphertext_len) {
    if (kem == NULL) return -1;

    // Allocate space for encapsulated key and ciphertext
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    uint8_t *ciphertext_kem = malloc(kem->length_ciphertext);
    if (shared_secret == NULL || ciphertext_kem == NULL) {
        free(shared_secret);
        free(ciphertext_kem);
        return -1;
    }

    // Encapsulate the key
    if (OQS_KEM_encaps(kem, ciphertext_kem, shared_secret, public_key) != OQS_SUCCESS) {
        free(shared_secret);
        free(ciphertext_kem);
        return -1;
    }

    // Now use the shared_secret to encrypt the plaintext using XOR
    *ciphertext = malloc(kem->length_ciphertext + plaintext_len);
    if (*ciphertext == NULL) {
        free(shared_secret);
        free(ciphertext_kem);
        return -1;
    }

    // Copy KEM ciphertext to the beginning of the final ciphertext
    memcpy(*ciphertext, ciphertext_kem, kem->length_ciphertext);

    // Encrypt the plaintext using XOR
    simple_xor_encrypt(shared_secret, kem->length_shared_secret, plaintext, plaintext_len, *ciphertext + kem->length_ciphertext);

    *ciphertext_len = kem->length_ciphertext + plaintext_len;

    free(shared_secret);
    free(ciphertext_kem);
    return 0;
}

// Decrypt data using PQC
int PQCModule_Decrypt(uint8_t *secret_key, size_t secret_key_len,
                      uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t **plaintext, size_t *plaintext_len) {
    if (kem == NULL) return -1;

    // Extract KEM ciphertext from the input ciphertext
    uint8_t *ciphertext_kem = ciphertext;
    size_t kem_length = kem->length_ciphertext;
    uint8_t *enc_message = ciphertext + kem_length;
    size_t enc_length = ciphertext_len - kem_length;

    // Generate shared secret from the KEM
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    if (shared_secret == NULL) return -1;

    // Decapsulate the key
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext_kem, secret_key) != OQS_SUCCESS) {
        free(shared_secret);
        return -1;
    }

    // Allocate space for the plaintext
    *plaintext = malloc(enc_length);
    if (*plaintext == NULL) {
        free(shared_secret);
        return -1;
    }

    // Decrypt the ciphertext using XOR
    simple_xor_encrypt(shared_secret, kem->length_shared_secret, enc_message, enc_length, *plaintext);

    *plaintext_len = enc_length;

    free(shared_secret);
    return 0;
}