#include <stdio.h>
#include <string.h>
#include "crypto_utils.h"

static int passed = 0;
static int failed = 0;

#define ASSERT(label, cond) \
	do { \
		if (cond) { \
			printf("  PASS  %s\n", label); \
			passed++; \
		} else { \
			printf("  FAIL  %s\n", label); \
			failed++; \
		} \
	} while (0)

static void test_hash_and_verify_master_password(void) {
	char stored[MASTER_STORED_HASH_SIZE];

	ASSERT("master hash is created",           hash_master_password("master-secret", stored, sizeof(stored)));
	ASSERT("correct master password verifies", verify_master_password("master-secret", stored));
	ASSERT("wrong master password is rejected", !verify_master_password("wrong-secret", stored));
}

static void test_derive_key_from_stored_hash(void) {
	char stored[MASTER_STORED_HASH_SIZE];
	unsigned char key[MASTER_KEY_BYTES];

	ASSERT("stored hash is created",                hash_master_password("derive-key", stored, sizeof(stored)));
	ASSERT("key is derived from stored hash",       derive_key_from_stored_hash(stored, key));
	ASSERT("derived key contains non-zero bytes",   memcmp(key, (unsigned char[MASTER_KEY_BYTES]){0}, MASTER_KEY_BYTES) != 0);
	ASSERT("malformed stored hash is rejected",     !derive_key_from_stored_hash("short:abcd", key));
}

static void test_encrypt_decrypt_roundtrip(void) {
	const unsigned char key[MASTER_KEY_BYTES] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	char encrypted[ENCRYPTED_SECRET_MAX];
	char plain[256];

	ASSERT("password encrypts successfully",  encrypt_secret("P@ssw0rd!2026", key, encrypted, sizeof(encrypted)));
	ASSERT("ciphertext format is recognized", is_encrypted_secret_format(encrypted));
	ASSERT("password decrypts successfully",  decrypt_secret(encrypted, key, plain, sizeof(plain)));
	ASSERT("decrypted value matches original", strcmp(plain, "P@ssw0rd!2026") == 0);
}

static void test_wrong_key_and_tamper_fail(void) {
	const unsigned char key[MASTER_KEY_BYTES] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
	};
	unsigned char wrong_key[MASTER_KEY_BYTES];
	char encrypted[ENCRYPTED_SECRET_MAX];
	char tampered[ENCRYPTED_SECRET_MAX];
	char plain[256];

	memcpy(wrong_key, key, sizeof(wrong_key));
	wrong_key[0] ^= 0xff;

	ASSERT("encryption for validation succeeds",        encrypt_secret("sensitive-value", key, encrypted, sizeof(encrypted)));
	ASSERT("decryption with wrong key fails",           !decrypt_secret(encrypted, wrong_key, plain, sizeof(plain)));

	strcpy(tampered, encrypted);
	tampered[strlen(tampered) - 1] = tampered[strlen(tampered) - 1] == '0' ? '1' : '0';
	ASSERT("decryption of tampered ciphertext fails",  !decrypt_secret(tampered, key, plain, sizeof(plain)));
}

static void test_invalid_inputs(void) {
	const unsigned char key[MASTER_KEY_BYTES] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20,
		0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
		0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xab, 0xcd
	};
	char encrypted[ENCRYPTED_SECRET_MAX];
	char plain[256];
	char too_small[8];

	ASSERT("empty string is rejected for encryption", !encrypt_secret("", key, encrypted, sizeof(encrypted)));
	ASSERT("small output buffer is rejected",         !encrypt_secret("hello", key, too_small, sizeof(too_small)));
	ASSERT("NULL ciphertext is rejected",             !decrypt_secret(NULL, key, plain, sizeof(plain)));
	ASSERT("malformed enc:v1 format is rejected",     !decrypt_secret("enc:v1:abcd:1234:beef", key, plain, sizeof(plain)));
	ASSERT("format with wrong length is not recognized", !is_encrypted_secret_format("enc:v1:abcd:1234:beef"));
	ASSERT("legacy format is recognized",            is_encrypted_secret_format("00112233445566778899aabb:abcd:00112233445566778899aabbccddeeff"));
	ASSERT("empty string is not recognized as format", !is_encrypted_secret_format(""));
}

int main(void) {
	printf("=== Crypto Utils Unit Tests ===\n\n");

	test_hash_and_verify_master_password();
	test_derive_key_from_stored_hash();
	test_encrypt_decrypt_roundtrip();
	test_wrong_key_and_tamper_fail();
	test_invalid_inputs();

	printf("\nResult: %d passed / %d failed\n", passed, failed);
	return failed > 0 ? 1 : 0;
}