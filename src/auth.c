#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"

#define INPUT_SIZE 256

#define PBKDF2_ITERATIONS 100000
#define SALT_BYTES        32
#define HASH_BYTES        32
/* "salt_hex:hash_hex\0" = 64 + 1 + 64 + 1 */
#define STORED_HASH_SIZE  (SALT_BYTES * 2 + 1 + HASH_BYTES * 2 + 1)

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

static int hash_master_password(const char *password, char *out_stored) {
	unsigned char salt[SALT_BYTES];
	unsigned char hash[HASH_BYTES];
	char salt_hex[SALT_BYTES * 2 + 1];
	char hash_hex[HASH_BYTES * 2 + 1];

	if (RAND_bytes(salt, SALT_BYTES) != 1) {
		fprintf(stderr, CHALK_RED("Failed to generate random salt.\n"));
		return 0;
	}

	if (PKCS5_PBKDF2_HMAC(password, -1,
	                      salt, SALT_BYTES,
	                      PBKDF2_ITERATIONS,
	                      EVP_sha256(),
	                      HASH_BYTES, hash) != 1) {
		fprintf(stderr, CHALK_RED("Failed to hash password.\n"));
		return 0;
	}

	hex_encode(salt, SALT_BYTES, salt_hex);
	hex_encode(hash, HASH_BYTES, hash_hex);
	snprintf(out_stored, STORED_HASH_SIZE, "%s:%s", salt_hex, hash_hex);
	return 1;
}

static int verify_master_password(const char *password, const char *stored) {
	unsigned char salt[SALT_BYTES];
	unsigned char expected_hash[HASH_BYTES];
	unsigned char actual_hash[HASH_BYTES];
	const char *colon;
	size_t salt_hex_len;

	colon = strchr(stored, ':');
	if (colon == NULL) {
		return 0;
	}

	salt_hex_len = (size_t)(colon - stored);
	if (salt_hex_len != SALT_BYTES * 2) {
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

int read_input(const char *prompt, char *buffer, size_t size) {
	printf("%s", prompt);
	fflush(stdout);

	if (fgets(buffer, size, stdin) == NULL) {
		return 0;
	}

	buffer[strcspn(buffer, "\n")] = '\0';
	return buffer[0] != '\0';
}

int read_secret(const char *prompt, char *buffer, size_t size) {
	struct termios old, new;
	int ok;

	printf("%s", prompt);
	fflush(stdout);

	tcgetattr(STDIN_FILENO, &old);
	new = old;
	new.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

	ok = (fgets(buffer, size, stdin) != NULL);

	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	printf("\n");

	if (!ok) return 0;
	buffer[strcspn(buffer, "\n")] = '\0';
	return buffer[0] != '\0';
}

int setup_master_password(sqlite3 *db) {
	sqlite3_stmt *stmt;
	char password[INPUT_SIZE];
	char confirm[INPUT_SIZE];
	char stored_hash[STORED_HASH_SIZE];
	const char *sql =
		"INSERT OR REPLACE INTO master_auth (id, password) VALUES (1, ?);";

	printf(CHALK_CYAN("Set a master password for this vault.\n"));

	if (!read_secret("Master password: ", password, sizeof(password))) {
		fprintf(stderr, CHALK_RED("Master password is required.\n"));
		return 0;
	}

	if (!read_secret("Confirm password: ", confirm, sizeof(confirm))) {
		fprintf(stderr, CHALK_RED("Password confirmation is required.\n"));
		return 0;
	}

	if (strcmp(password, confirm) != 0) {
		fprintf(stderr, CHALK_RED("Passwords do not match.\n"));
		return 0;
	}

	if (!hash_master_password(password, stored_hash)) {
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		return 0;
	}

	sqlite3_bind_text(stmt, 1, stored_hash, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, CHALK_RED("Failed to save master password: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return 0;
	}

	sqlite3_finalize(stmt);
	printf(CHALK_GREEN("Master password set successfully.\n"));
	return 1;
}

int authenticate_master(const char *db_path) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char input[INPUT_SIZE];
	const char *sql = "SELECT password FROM master_auth WHERE id = 1;";
	int authenticated = 0;

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *stored_hash = (const char *)sqlite3_column_text(stmt, 0);

		if (!read_secret("Enter master password: ", input, sizeof(input))) {
			sqlite3_finalize(stmt);
			sqlite3_close(db);
			return 0;
		}

		if (verify_master_password(input, stored_hash)) {
			authenticated = 1;
		} else {
			fprintf(stderr, CHALK_RED("Authentication failed.\n"));
		}
	} else {
		fprintf(stderr, CHALK_YELLOW("No master password set. Run init first.\n"));
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return authenticated;
}
