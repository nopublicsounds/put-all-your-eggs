#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "crypto_utils.h"
#include "cmd_private.h"
#include "commands.h"

int cmd_migrate(const char *db_path) {
	sqlite3 *db;
	sqlite3_stmt *select_stmt = NULL;
	sqlite3_stmt *update_stmt = NULL;
	unsigned char master_key[MASTER_KEY_BYTES];
	const char *select_sql = "SELECT site, password FROM entries;";
	const char *update_sql = "UPDATE entries SET password = ? WHERE site = ?;";
	int migrated = 0;
	int skipped = 0;

	if (!db_must_exist(db_path)) return 1;

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

	if (sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL) != SQLITE_OK) {
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
			skipped++;
			continue;
		}

		if (decrypt_secret(stored, master_key, plain, sizeof(plain))) {
			if (strncmp(stored, "enc:v1:", 7) == 0) {
				skipped++;
				continue;
			}
		} else {
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

		if (!encrypt_secret(plain, master_key, encrypted, sizeof(encrypted))) {
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

		migrated++;
	}

	sqlite3_finalize(update_stmt);
	sqlite3_finalize(select_stmt);

	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to commit migration: %s\n"), sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		sqlite3_close(db);
		return 1;
	}

	printf(CHALK_GREEN("Migration complete. migrated=%d, skipped=%d\n"), migrated, skipped);
	sqlite3_close(db);
	return 0;
}
