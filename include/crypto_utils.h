#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>

#define MASTER_KEY_BYTES 32
#define MASTER_STORED_HASH_SIZE 130
#define ENCRYPTED_SECRET_MAX 1024

int hash_master_password(const char *password, char *out_stored, size_t out_size);
int verify_master_password(const char *password, const char *stored);
int derive_key_from_stored_hash(const char *stored_hash, unsigned char out_key[MASTER_KEY_BYTES]);
int encrypt_secret(const char *plain, const unsigned char key[MASTER_KEY_BYTES], char *out_encrypted, size_t out_size);
int decrypt_secret(const char *encrypted, const unsigned char key[MASTER_KEY_BYTES], char *out_plain, size_t out_size);
int is_encrypted_secret_format(const char *value);

#endif
