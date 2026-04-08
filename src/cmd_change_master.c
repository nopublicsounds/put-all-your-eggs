#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"
#include "crypto_utils.h"
#include "cmd_private.h"
#include "commands.h"

int cmd_change_master(const char *db_path) {
	sqlite3 *db;
	sqlite3_stmt *select_stmt = NULL;
	sqlite3_stmt *update_stmt = NULL;
	sqlite3_stmt *master_update_stmt = NULL;
	unsigned char old_key[MASTER_KEY_BYTES];
	unsigned char new_key[MASTER_KEY_BYTES];
	char new_password[INPUT_SIZE];
	char confirm_password[INPUT_SIZE];
	char new_stored_hash[MASTER_STORED_HASH_SIZE];
	const char *select_sql = "SELECT site, password FROM entries;";
	const char *update_entry_sql = "UPDATE entries SET password = ? WHERE site = ?;";
	const char *update_master_sql = "UPDATE master_auth SET password = ? WHERE id = 1;";

	if (!db_must_exist(db_path)) return 1;

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (!table_exists(db, "master_auth")) {
		fprintf(stderr, CHALK_YELLOW("Master auth table not found. Run init first.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (!get_master_hash_key(db, old_key)) {
		fprintf(stderr, CHALK_RED("Master hash key not available. Run init first.\n"));
		sqlite3_close(db);
		return 1;
	}

	printf(CHALK_CYAN("Set a new master password.\n"));

	if (!read_secret("New master password: ", new_password, sizeof(new_password))) {
		fprintf(stderr, CHALK_RED("Master password is required.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (!read_secret("Confirm new password: ", confirm_password, sizeof(confirm_password))) {
		fprintf(stderr, CHALK_RED("Password confirmation is required.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (strcmp(new_password, confirm_password) != 0) {
		fprintf(stderr, CHALK_RED("Passwords do not match.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (!hash_master_password(new_password, new_stored_hash, sizeof(new_stored_hash))) {
		fprintf(stderr, CHALK_RED("Failed to hash new master password.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (!derive_key_from_stored_hash(new_stored_hash, new_key)) {
		fprintf(stderr, CHALK_RED("Failed to derive new master key.\n"));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to start transaction: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare select SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_prepare_v2(db, update_entry_sql, -1, &update_stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare update SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(select_stmt);
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		sqlite3_close(db);
		return 1;
	}

	while (sqlite3_step(select_stmt) == SQLITE_ROW) {
		const char *site = (const char *)sqlite3_column_text(select_stmt, 0);
		const char *stored = (const char *)sqlite3_column_text(select_stmt, 1);
		char plain[INPUT_SIZE];
		char encrypted[ENCRYPTED_SECRET_MAX];

		if (site == NULL || stored == NULL) {
			continue;
		}

		if (!decrypt_secret(stored, old_key, plain, sizeof(plain))) {
			if (is_encrypted_secret_format(stored)) {
				fprintf(stderr, CHALK_RED("Failed to decrypt existing encrypted entry: %s\n"), site);
				sqlite3_finalize(update_stmt);
				sqlite3_finalize(select_stmt);
				sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
				sqlite3_close(db);
				return 1;
			}
			snprintf(plain, sizeof(plain), "%s", stored);
		}

		if (!encrypt_secret(plain, new_key, encrypted, sizeof(encrypted))) {
			fprintf(stderr, CHALK_RED("Failed to encrypt entry: %s\n"), site);
			sqlite3_finalize(update_stmt);
			sqlite3_finalize(select_stmt);
			sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
			sqlite3_close(db);
			return 1;
		}

		sqlite3_reset(update_stmt);
		sqlite3_clear_bindings(update_stmt);
		sqlite3_bind_text(update_stmt, 1, encrypted, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(update_stmt, 2, site, -1, SQLITE_TRANSIENT);

		if (sqlite3_step(update_stmt) != SQLITE_DONE) {
			fprintf(stderr, CHALK_RED("Failed to update entry: %s\n"), site);
			sqlite3_finalize(update_stmt);
			sqlite3_finalize(select_stmt);
			sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
			sqlite3_close(db);
			return 1;
		}
	}

	sqlite3_finalize(update_stmt);
	sqlite3_finalize(select_stmt);

	if (sqlite3_prepare_v2(db, update_master_sql, -1, &master_update_stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare master update SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		sqlite3_close(db);
		return 1;
	}

	sqlite3_bind_text(master_update_stmt, 1, new_stored_hash, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(master_update_stmt) != SQLITE_DONE) {
		fprintf(stderr, CHALK_RED("Failed to update master password: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(master_update_stmt);
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		sqlite3_close(db);
		return 1;
	}

	sqlite3_finalize(master_update_stmt);

	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to commit master password change: %s\n"), sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		sqlite3_close(db);
		return 1;
	}

	printf(CHALK_GREEN("Master password changed successfully.\n"));

	for (size_t i = 0; i < sizeof(new_password); i++) {
		new_password[i] = '\0';
	}
	for (size_t i = 0; i < sizeof(confirm_password); i++) {
		confirm_password[i] = '\0';
	}

	sqlite3_close(db);
	return 0;
}
