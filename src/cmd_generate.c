#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "chalk.h"
#include "cmd_private.h"
#include "commands.h"
#include "db.h"
#include "auth.h"
#include "crypto_utils.h"

int cmd_generate(const char *db_path, int length, unsigned int flags) {
	char *password;
	char answer[8];
	char site[INPUT_SIZE];
	char username[INPUT_SIZE];
	char encrypted_password[ENCRYPTED_SECRET_MAX];
	unsigned char master_key[MASTER_KEY_BYTES];
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int exists;
	const char *sql =
		"INSERT INTO entries (site, username, password) VALUES (?, ?, ?) "
		"ON CONFLICT(site) DO UPDATE SET username = excluded.username, password = excluded.password;";

	/* minimum length = number of active groups (guaranteed by generate_password_ex) */
	if (length <= 0) {
		fprintf(stderr, CHALK_RED("Length must be a positive integer.\n"));
		return 1;
	}

	password = malloc((size_t)length + 1);
	if (password == NULL) {
		fprintf(stderr, CHALK_RED("Failed to allocate password buffer.\n"));
		return 1;
	}

	if (!generate_password_ex(password, length, flags)) {
		int n_groups = (int)((flags & PW_FLAG_LOWER) != 0) + (int)((flags & PW_FLAG_UPPER) != 0)
		             + (int)((flags & PW_FLAG_DIGIT) != 0) + (int)((flags & PW_FLAG_SPECIAL) != 0);
		if (n_groups == 0) {
			fprintf(stderr, CHALK_RED("No character groups selected.\n"));
		} else {
			fprintf(stderr, CHALK_RED("Length must be at least %d for the selected character groups.\n"), n_groups);
		}
		free(password);
		return 1;
	}

	printf(CHALK_GREEN("Generated password: %s\n"), password);

	if (!read_input("Save to vault? (y/n): ", answer, sizeof(answer))) {
		free(password);
		return 0;
	}

	if (answer[0] != 'y' && answer[0] != 'Y') {
		free(password);
		return 0;
	}

	if (!read_input("Site: ", site, sizeof(site))) {
		free(password);
		return 0;
	}

	if (!read_input("Username: ", username, sizeof(username))) {
		free(password);
		return 0;
	}

	if (!db_must_exist(db_path)) {
		free(password);
		return 1;
	}

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		free(password);
		return 1;
	}

	if (!table_exists(db, "entries")) {
		fprintf(stderr, CHALK_YELLOW("Table 'entries' not found. Run init first.\n"));
		sqlite3_close(db);
		free(password);
		return 1;
	}

	if (!get_master_hash_key(db, master_key)) {
		fprintf(stderr, CHALK_RED("Master hash key not available. Run init first.\n"));
		sqlite3_close(db);
		free(password);
		return 1;
	}

	if (!encrypt_secret(password, master_key, encrypted_password, sizeof(encrypted_password))) {
		fprintf(stderr, CHALK_RED("Failed to encrypt password.\n"));
		sqlite3_close(db);
		free(password);
		return 1;
	}

	free(password);
	password = NULL;

	exists = entry_exists(db, site);
	if (exists && !confirm_overwrite(db_path, site)) {
		printf(CHALK_YELLOW("Save cancelled.\n"));
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	sqlite3_bind_text(stmt, 1, site,               -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, username,            -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, encrypted_password,  -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, CHALK_RED("Failed to save: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return 1;
	}

	if (exists) {
		printf(CHALK_GREEN("Updated: %s\n"), site);
	} else {
		printf(CHALK_GREEN("Saved: %s\n"), site);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}
