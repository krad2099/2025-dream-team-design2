#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>


int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; 
    int result;

    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; 

    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; 
    }
    return 0;
}

int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; 
    int result; 

    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; 

    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; 
    }
    return 0;
}

int hash(void *data, size_t len, uint8_t *hash_out) {
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}

#endif
