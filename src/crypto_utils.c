#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

#define PBKDF2_ITERATIONS 100000
#define SALT_BYTES 32
#define HASH_BYTES 32
#define GCM_IV_BYTES 12
#define GCM_TAG_BYTES 16
#define LEGACY_PARTS 3
#define V1_PARTS 5
#define ENC_PREFIX "enc:v1:"

static int hex_value(char c, unsigned int *out) {
	if (c >= '0' && c <= '9') {
		*out = (unsigned int)(c - '0');
		return 1;
	}
	if (c >= 'a' && c <= 'f') {
		*out = (unsigned int)(c - 'a' + 10);
		return 1;
	}
	return 0;
}

static void hex_encode(const unsigned char *src, size_t len, char *dst) {
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		dst[i * 2] = hex[(src[i] >> 4) & 0x0f];
		dst[i * 2 + 1] = hex[src[i] & 0x0f];
	}
	dst[len * 2] = '\0';
}

static int hex_decode(const char *src, unsigned char *dst, size_t len) {
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned int hi;
		unsigned int lo;

		if (!hex_value(src[i * 2], &hi)) return 0;
		if (!hex_value(src[i * 2 + 1], &lo)) return 0;
		dst[i] = (unsigned char)((hi << 4) | lo);
	}

	return 1;
}

static int parse_parts(const char *input, char *parts[5], int *out_count) {
	char *token;
	int count = 0;

	token = strtok((char *)input, ":");
	while (token != NULL && count < 5) {
		parts[count++] = token;
		token = strtok(NULL, ":");
	}
	if (token != NULL) {
		return 0;
	}
	*out_count = count;
	return 1;
}

int hash_master_password(const char *password, char *out_stored, size_t out_size) {
	unsigned char salt[SALT_BYTES];
	unsigned char hash[HASH_BYTES];
	char salt_hex[SALT_BYTES * 2 + 1];
	char hash_hex[HASH_BYTES * 2 + 1];

	if (out_size < MASTER_STORED_HASH_SIZE) {
		return 0;
	}
	if (RAND_bytes(salt, SALT_BYTES) != 1) {
		return 0;
	}
	if (PKCS5_PBKDF2_HMAC(password, -1,
	                      salt, SALT_BYTES,
	                      PBKDF2_ITERATIONS,
	                      EVP_sha256(),
	                      HASH_BYTES, hash) != 1) {
		return 0;
	}

	hex_encode(salt, SALT_BYTES, salt_hex);
	hex_encode(hash, HASH_BYTES, hash_hex);
	snprintf(out_stored, out_size, "%s:%s", salt_hex, hash_hex);
	return 1;
}

int verify_master_password(const char *password, const char *stored) {
	unsigned char salt[SALT_BYTES];
	unsigned char expected_hash[HASH_BYTES];
	unsigned char actual_hash[HASH_BYTES];
	const char *colon;

	if (stored == NULL) {
		return 0;
	}
	colon = strchr(stored, ':');
	if (colon == NULL || (size_t)(colon - stored) != SALT_BYTES * 2) {
		return 0;
	}
	if (strlen(colon + 1) != HASH_BYTES * 2) {
		return 0;
	}

	if (!hex_decode(stored, salt, SALT_BYTES)) {
		return 0;
	}
	if (!hex_decode(colon + 1, expected_hash, HASH_BYTES)) {
		return 0;
	}

	if (PKCS5_PBKDF2_HMAC(password, -1,
	                      salt, SALT_BYTES,
	                      PBKDF2_ITERATIONS,
	                      EVP_sha256(),
	                      HASH_BYTES, actual_hash) != 1) {
		return 0;
	}

	return CRYPTO_memcmp(actual_hash, expected_hash, HASH_BYTES) == 0;
}

int derive_key_from_stored_hash(const char *stored_hash, unsigned char out_key[MASTER_KEY_BYTES]) {
	const char *colon;

	if (stored_hash == NULL) {
		return 0;
	}
	colon = strchr(stored_hash, ':');
	if (colon == NULL) {
		return 0;
	}
	if (strlen(colon + 1) != MASTER_KEY_BYTES * 2) {
		return 0;
	}

	return hex_decode(colon + 1, out_key, MASTER_KEY_BYTES);
}

int is_encrypted_secret_format(const char *value) {
	char copy[ENCRYPTED_SECRET_MAX];
	char *parts[5];
	int count;
	const char *iv_hex;
	const char *ct_hex;
	const char *tag_hex;

	if (value == NULL || strlen(value) >= sizeof(copy)) {
		return 0;
	}

	strcpy(copy, value);
	if (!parse_parts(copy, parts, &count)) {
		return 0;
	}

	if (count == V1_PARTS && strcmp(parts[0], "enc") == 0 && strcmp(parts[1], "v1") == 0) {
		iv_hex = parts[2];
		ct_hex = parts[3];
		tag_hex = parts[4];
	} else if (count == LEGACY_PARTS) {
		iv_hex = parts[0];
		ct_hex = parts[1];
		tag_hex = parts[2];
	} else {
		return 0;
	}

	if (strlen(iv_hex) != GCM_IV_BYTES * 2 || strlen(tag_hex) != GCM_TAG_BYTES * 2) {
		return 0;
	}
	if (strlen(ct_hex) == 0 || (strlen(ct_hex) % 2) != 0) {
		return 0;
	}
	return 1;
}

int encrypt_secret(const char *plain, const unsigned char key[MASTER_KEY_BYTES], char *out_encrypted, size_t out_size) {
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[GCM_IV_BYTES];
	unsigned char ciphertext[256];
	unsigned char tag[GCM_TAG_BYTES];
	char iv_hex[GCM_IV_BYTES * 2 + 1];
	char ct_hex[sizeof(ciphertext) * 2 + 1];
	char tag_hex[GCM_TAG_BYTES * 2 + 1];
	int len;
	int ciphertext_len;
	int plain_len;

	plain_len = (int)strlen(plain);
	if (plain_len <= 0 || plain_len >= (int)sizeof(ciphertext)) {
		return 0;
	}
	if (RAND_bytes(iv, sizeof(iv)) != 1) {
		return 0;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		return 0;
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_BYTES, NULL) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)plain, plain_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	ciphertext_len += len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, tag) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	EVP_CIPHER_CTX_free(ctx);

	hex_encode(iv, sizeof(iv), iv_hex);
	hex_encode(ciphertext, (size_t)ciphertext_len, ct_hex);
	hex_encode(tag, sizeof(tag), tag_hex);

	if ((size_t)snprintf(out_encrypted, out_size, "%s%s:%s:%s", ENC_PREFIX, iv_hex, ct_hex, tag_hex) >= out_size) {
		return 0;
	}
	return 1;
}

int decrypt_secret(const char *encrypted, const unsigned char key[MASTER_KEY_BYTES], char *out_plain, size_t out_size) {
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[GCM_IV_BYTES];
	unsigned char ciphertext[256];
	unsigned char tag[GCM_TAG_BYTES];
	unsigned char plain[256];
	char copy[ENCRYPTED_SECRET_MAX];
	char *parts[5];
	const char *iv_hex;
	const char *ct_hex;
	const char *tag_hex;
	int count;
	int ct_len;
	int len;
	int plain_len;

	if (encrypted == NULL || strlen(encrypted) >= sizeof(copy)) {
		return 0;
	}

	strcpy(copy, encrypted);
	if (!parse_parts(copy, parts, &count)) {
		return 0;
	}

	if (count == V1_PARTS && strcmp(parts[0], "enc") == 0 && strcmp(parts[1], "v1") == 0) {
		iv_hex = parts[2];
		ct_hex = parts[3];
		tag_hex = parts[4];
	} else if (count == LEGACY_PARTS) {
		iv_hex = parts[0];
		ct_hex = parts[1];
		tag_hex = parts[2];
	} else {
		return 0;
	}

	if (strlen(iv_hex) != GCM_IV_BYTES * 2 || strlen(tag_hex) != GCM_TAG_BYTES * 2) {
		return 0;
	}
	if (strlen(ct_hex) == 0 || strlen(ct_hex) >= sizeof(ciphertext) * 2 || (strlen(ct_hex) % 2) != 0) {
		return 0;
	}

	ct_len = (int)(strlen(ct_hex) / 2);
	if (!hex_decode(iv_hex, iv, sizeof(iv))) return 0;
	if (!hex_decode(ct_hex, ciphertext, (size_t)ct_len)) return 0;
	if (!hex_decode(tag_hex, tag, sizeof(tag))) return 0;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		return 0;
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_BYTES, NULL) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_DecryptUpdate(ctx, plain, &len, ciphertext, ct_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	plain_len = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_BYTES, tag) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_DecryptFinal_ex(ctx, plain + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	plain_len += len;
	EVP_CIPHER_CTX_free(ctx);

	if ((size_t)plain_len >= out_size) {
		return 0;
	}
	plain[plain_len] = '\0';
	memcpy(out_plain, plain, (size_t)plain_len + 1);
	return 1;
}
