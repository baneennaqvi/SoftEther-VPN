
#ifndef PQCMODULE_H
#define PQCMODULE_H

#include <stdint.h>
#include <stddef.h>

// Forward declaration of OQS_KEM structure from OQS library
typedef struct OQS_KEM OQS_KEM;

// Function to initialize the PQC module
int PQCModule_Init();

// Function to clean up the PQC module
void PQCModule_Cleanup();

// Function to generate a key pair
int PQCModule_GenerateKeyPair(uint8_t **public_key, size_t *public_key_len,
                              uint8_t **secret_key, size_t *secret_key_len);

// Function to encrypt plaintext using PQC
int PQCModule_Encrypt(uint8_t *public_key, size_t public_key_len,
                      uint8_t *plaintext, size_t plaintext_len,
                      uint8_t **ciphertext, size_t *ciphertext_len);

// Function to decrypt ciphertext using PQC
int PQCModule_Decrypt(uint8_t *secret_key, size_t secret_key_len,
                      uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t **plaintext, size_t *plaintext_len);

#endif // PQCMODULE_H
