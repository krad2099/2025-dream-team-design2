/**
 * @file simple_crypto.h
 * Simplified Crypto API Header 
 * (Using AES-128 in ECB mode for symmetric encryption and MD5 for hashing)
 */
#if CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE      // Typically 16 bytes
#define KEY_SIZE 16                    // AES-128 uses a 16-byte key
#define HASH_SIZE MD5_DIGEST_SIZE      // MD5 produces a 16-byte digest

/******************************** FUNCTION PROTOTYPES ********************************/
/**
 * Encrypts plaintext using AES-128 in ECB mode.
 * The plaintext length must be a positive multiple of BLOCK_SIZE.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);

/**
 * Decrypts ciphertext using AES-128 in ECB mode.
 * The ciphertext length must be a positive multiple of BLOCK_SIZE.
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);

/**
 * Hashes arbitrary-length data using MD5.
 */
int hash(void *data, size_t len, uint8_t *hash_out);

#endif // ECTF_CRYPTO_H
#endif // CRYPTO_EXAMPLE
