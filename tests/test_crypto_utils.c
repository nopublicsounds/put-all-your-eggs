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

	ASSERT("master 해시 생성", hash_master_password("master-secret", stored, sizeof(stored)));
	ASSERT("올바른 master 비밀번호 검증", verify_master_password("master-secret", stored));
	ASSERT("틀린 master 비밀번호 거부", !verify_master_password("wrong-secret", stored));
}

static void test_derive_key_from_stored_hash(void) {
	char stored[MASTER_STORED_HASH_SIZE];
	unsigned char key[MASTER_KEY_BYTES];

	ASSERT("저장 해시 생성", hash_master_password("derive-key", stored, sizeof(stored)));
	ASSERT("저장 해시에서 키 파생", derive_key_from_stored_hash(stored, key));
	ASSERT("파생 키 길이만큼 0이 아닌 값 존재", memcmp(key, (unsigned char[MASTER_KEY_BYTES]){0}, MASTER_KEY_BYTES) != 0);
	ASSERT("잘못된 저장 해시 거부", !derive_key_from_stored_hash("short:abcd", key));
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

	ASSERT("비밀번호 암호화 성공", encrypt_secret("P@ssw0rd!2026", key, encrypted, sizeof(encrypted)));
	ASSERT("암호문 포맷 인식", is_encrypted_secret_format(encrypted));
	ASSERT("비밀번호 복호화 성공", decrypt_secret(encrypted, key, plain, sizeof(plain)));
	ASSERT("복호화 결과 원문 일치", strcmp(plain, "P@ssw0rd!2026") == 0);
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

	ASSERT("검증용 암호화 성공", encrypt_secret("sensitive-value", key, encrypted, sizeof(encrypted)));
	ASSERT("다른 키로 복호화 실패", !decrypt_secret(encrypted, wrong_key, plain, sizeof(plain)));

	strcpy(tampered, encrypted);
	tampered[strlen(tampered) - 1] = tampered[strlen(tampered) - 1] == '0' ? '1' : '0';
	ASSERT("변조된 암호문 복호화 실패", !decrypt_secret(tampered, key, plain, sizeof(plain)));
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

	ASSERT("빈 문자열 암호화 거부", !encrypt_secret("", key, encrypted, sizeof(encrypted)));
	ASSERT("작은 출력 버퍼 거부", !encrypt_secret("hello", key, too_small, sizeof(too_small)));
	ASSERT("NULL 암호문 거부", !decrypt_secret(NULL, key, plain, sizeof(plain)));
	ASSERT("잘못된 enc:v1 포맷 거부", !decrypt_secret("enc:v1:abcd:1234:beef", key, plain, sizeof(plain)));
	ASSERT("길이 잘못된 포맷 미인식", !is_encrypted_secret_format("enc:v1:abcd:1234:beef"));
	ASSERT("legacy 형식 인식", is_encrypted_secret_format("00112233445566778899aabb:abcd:00112233445566778899aabbccddeeff"));
	ASSERT("빈 문자열 포맷 미인식", !is_encrypted_secret_format(""));
}

int main(void) {
	printf("=== crypto_utils 단위 테스트 ===\n\n");

	test_hash_and_verify_master_password();
	test_derive_key_from_stored_hash();
	test_encrypt_decrypt_roundtrip();
	test_wrong_key_and_tamper_fail();
	test_invalid_inputs();

	printf("\n결과: %d 통과 / %d 실패\n", passed, failed);
	return failed > 0 ? 1 : 0;
}