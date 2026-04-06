#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define PBKDF2_ITERATIONS 100000
#define SALT_BYTES        32
#define HASH_BYTES        32
#define STORED_HASH_SIZE  (SALT_BYTES * 2 + 1 + HASH_BYTES * 2 + 1)

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

/* ── 아래는 auth.c의 static 함수를 그대로 복사해 테스트 ── */

static void hex_encode(const unsigned char *src, size_t len, char *dst) {
	static const char hex[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < len; i++) {
		dst[i * 2]     = hex[(src[i] >> 4) & 0xf];
		dst[i * 2 + 1] = hex[src[i] & 0xf];
	}
	dst[len * 2] = '\0';
}

static int hex_decode(const char *src, unsigned char *dst, size_t len) {
	size_t i;
	for (i = 0; i < len; i++) {
		unsigned int hi, lo;
		char c;

		c = src[i * 2];
		if (c >= '0' && c <= '9') hi = (unsigned int)(c - '0');
		else if (c >= 'a' && c <= 'f') hi = (unsigned int)(c - 'a' + 10);
		else return 0;

		c = src[i * 2 + 1];
		if (c >= '0' && c <= '9') lo = (unsigned int)(c - '0');
		else if (c >= 'a' && c <= 'f') lo = (unsigned int)(c - 'a' + 10);
		else return 0;

		dst[i] = (unsigned char)((hi << 4) | lo);
	}
	return 1;
}

static int hash_password(const char *password, char *out_stored) {
	unsigned char salt[SALT_BYTES];
	unsigned char hash[HASH_BYTES];
	char salt_hex[SALT_BYTES * 2 + 1];
	char hash_hex[HASH_BYTES * 2 + 1];

	if (RAND_bytes(salt, SALT_BYTES) != 1) return 0;

	if (PKCS5_PBKDF2_HMAC(password, -1,
	                      salt, SALT_BYTES,
	                      PBKDF2_ITERATIONS,
	                      EVP_sha256(),
	                      HASH_BYTES, hash) != 1) return 0;

	hex_encode(salt, SALT_BYTES, salt_hex);
	hex_encode(hash, HASH_BYTES, hash_hex);
	snprintf(out_stored, STORED_HASH_SIZE, "%s:%s", salt_hex, hash_hex);
	return 1;
}

static int verify_password(const char *password, const char *stored) {
	unsigned char salt[SALT_BYTES];
	unsigned char expected_hash[HASH_BYTES];
	unsigned char actual_hash[HASH_BYTES];
	const char *colon;
	size_t salt_hex_len;

	colon = strchr(stored, ':');
	if (colon == NULL) return 0;

	salt_hex_len = (size_t)(colon - stored);
	if (salt_hex_len != SALT_BYTES * 2) return 0;

	if (!hex_decode(stored, salt, SALT_BYTES)) return 0;
	if (!hex_decode(colon + 1, expected_hash, HASH_BYTES)) return 0;

	if (PKCS5_PBKDF2_HMAC(password, -1,
	                      salt, SALT_BYTES,
	                      PBKDF2_ITERATIONS,
	                      EVP_sha256(),
	                      HASH_BYTES, actual_hash) != 1) return 0;

	return CRYPTO_memcmp(actual_hash, expected_hash, HASH_BYTES) == 0;
}

/* ── 테스트 케이스 ── */

static void test_hash_produces_stored_format(void) {
	char stored[STORED_HASH_SIZE];
	const char *colon;
	int ok = hash_password("secret123", stored);

	ASSERT("hash 생성 성공", ok);
	ASSERT("저장 형식에 콜론 포함", strchr(stored, ':') != NULL);

	colon = strchr(stored, ':');
	ASSERT("솔트 hex 길이 == 64", colon != NULL && (colon - stored) == SALT_BYTES * 2);
	ASSERT("해시 hex 길이 == 64", colon != NULL && strlen(colon + 1) == HASH_BYTES * 2);
}

static void test_correct_password_verifies(void) {
	char stored[STORED_HASH_SIZE];
	hash_password("correct_horse", stored);
	ASSERT("올바른 비밀번호 검증 통과", verify_password("correct_horse", stored));
}

static void test_wrong_password_fails(void) {
	char stored[STORED_HASH_SIZE];
	hash_password("correct_horse", stored);
	ASSERT("틀린 비밀번호 검증 실패", !verify_password("wrong_horse", stored));
}

static void test_same_password_different_hashes(void) {
	char stored1[STORED_HASH_SIZE];
	char stored2[STORED_HASH_SIZE];
	hash_password("samepassword", stored1);
	hash_password("samepassword", stored2);
	ASSERT("같은 비밀번호도 솔트 달라 해시 다름", strcmp(stored1, stored2) != 0);
}

static void test_each_stored_verifies_only_its_own(void) {
	char stored1[STORED_HASH_SIZE];
	char stored2[STORED_HASH_SIZE];
	hash_password("password_A", stored1);
	hash_password("password_B", stored2);
	ASSERT("stored1은 password_A만 통과", verify_password("password_A", stored1));
	ASSERT("stored1은 password_B 거부",  !verify_password("password_B", stored1));
	ASSERT("stored2는 password_B만 통과", verify_password("password_B", stored2));
	ASSERT("stored2는 password_A 거부",  !verify_password("password_A", stored2));
}

static void test_empty_password(void) {
	char stored[STORED_HASH_SIZE];
	/* 빈 문자열도 해싱/검증 가능해야 함 */
	ASSERT("빈 비밀번호 해시 생성", hash_password("", stored));
	ASSERT("빈 비밀번호 검증 통과", verify_password("", stored));
	ASSERT("빈 비밀번호 != 다른 값", !verify_password("notempty", stored));
}

static void test_malformed_stored(void) {
	ASSERT("콜론 없는 입력 거부",        !verify_password("pw", "deadbeef"));
	ASSERT("솔트 길이 부족 거부",        !verify_password("pw", "aabb:1234"));
	ASSERT("빈 문자열 거부",             !verify_password("pw", ""));
}

static void test_hex_roundtrip(void) {
	unsigned char original[SALT_BYTES];
	unsigned char decoded[SALT_BYTES];
	char encoded[SALT_BYTES * 2 + 1];
	size_t i;
	int match;

	RAND_bytes(original, SALT_BYTES);
	hex_encode(original, SALT_BYTES, encoded);
	hex_decode(encoded, decoded, SALT_BYTES);

	match = 1;
	for (i = 0; i < SALT_BYTES; i++) {
		if (original[i] != decoded[i]) { match = 0; break; }
	}
	ASSERT("hex encode → decode 라운드트립", match);
}

int main(void) {
	printf("=== 해싱 단위 테스트 ===\n\n");

	test_hash_produces_stored_format();
	test_correct_password_verifies();
	test_wrong_password_fails();
	test_same_password_different_hashes();
	test_each_stored_verifies_only_its_own();
	test_empty_password();
	test_malformed_stored();
	test_hex_roundtrip();

	printf("\n결과: %d 통과 / %d 실패\n", passed, failed);
	return failed > 0 ? 1 : 0;
}
