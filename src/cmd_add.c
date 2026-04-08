#include <stdio.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"
#include "crypto_utils.h"
#include "cmd_private.h"
#include "commands.h"

int cmd_add(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char username[INPUT_SIZE];
	char password[INPUT_SIZE];
	char encrypted_password[ENCRYPTED_SECRET_MAX];
	unsigned char master_key[MASTER_KEY_BYTES];
	int exists;
	const char *sql =
		"INSERT INTO entries (site, username, password) VALUES (?, ?, ?) "
		"ON CONFLICT(site) DO UPDATE SET username = excluded.username, password = excluded.password;";

	if (!db_must_exist(db_path)) return 1;

	if (!read_input("Username: ", username, sizeof(username))) return 1;
	if (!read_input("Password: ", password, sizeof(password))) return 1;

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (!table_exists(db, "entries")) {
		fprintf(stderr, CHALK_YELLOW("Table 'entries' not found. Run init first.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (!get_master_hash_key(db, master_key)) {
		fprintf(stderr, CHALK_RED("Master hash key not available. Run init first.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (!encrypt_secret(password, master_key, encrypted_password, sizeof(encrypted_password))) {
		fprintf(stderr, CHALK_RED("Failed to encrypt password.\n"));
		sqlite3_close(db);
		return 1;
	}

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

	sqlite3_bind_text(stmt, 1, site,     -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, encrypted_password, -1, SQLITE_TRANSIENT);

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
