#include <stdio.h>
#include <sqlite3.h>
#include "chalk.h"
#include "crypto_utils.h"
#include "auth.h"
#include "cmd_private.h"
#include "commands.h"

int cmd_get(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	unsigned char master_key[MASTER_KEY_BYTES];
	char decrypted_password[INPUT_SIZE];
	const char *stored_password;
	const char *sql =
		"SELECT username, password FROM entries WHERE site = ?;";

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (!get_master_hash_key(db, master_key)) {
		fprintf(stderr, CHALK_RED("Master hash key not available. Run init first.\n"));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return 1;
	}

	sqlite3_bind_text(stmt, 1, site, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		stored_password = (const char *)sqlite3_column_text(stmt, 1);
		if (stored_password == NULL) {
			stored_password = "";
		}

		if (!decrypt_secret(stored_password, master_key, decrypted_password, sizeof(decrypted_password))) {
			if (!is_encrypted_secret_format(stored_password)) {
				snprintf(decrypted_password, sizeof(decrypted_password), "%s", stored_password);
			} else {
				fprintf(stderr, CHALK_RED("Failed to decrypt password.\n"));
				sqlite3_finalize(stmt);
				sqlite3_close(db);
				return 1;
			}
		}

		const char *username = (const char *)sqlite3_column_text(stmt, 0);

		printf("Site     : %s\n", site);
		printf("Username : %s\n", username);
		printf("Password : %s\n", decrypted_password);

		if (prompt_yes_no("Copy username to clipboard? (y/N): ")) {
			if (copy_to_clipboard(username)) {
				printf(CHALK_GREEN("Username copied to clipboard.\n"));
			} else {
				fprintf(stderr, CHALK_YELLOW("Clipboard copy failed. Install xclip, xsel, or wl-copy.\n"));
			}
		}

		if (prompt_yes_no("Copy password to clipboard? (y/N): ")) {
			if (copy_to_clipboard(decrypted_password)) {
				printf(CHALK_GREEN("Password copied to clipboard.\n"));
			} else {
				fprintf(stderr, CHALK_YELLOW("Clipboard copy failed. Install xclip, xsel, or wl-copy.\n"));
			}
		}
	} else {
		fprintf(stderr, CHALK_YELLOW("No entry found: %s\n"), site);
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return 1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}
