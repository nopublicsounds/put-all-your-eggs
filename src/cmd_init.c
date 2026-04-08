#include <stdio.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"
#include "commands.h"

int cmd_init(const char *db_path) {
	sqlite3 *db;
	char *errmsg = NULL;
	const char *sql =
		"CREATE TABLE IF NOT EXISTS entries ("
		"  site     TEXT PRIMARY KEY,"
		"  username TEXT NOT NULL,"
		"  password TEXT NOT NULL"
		");";

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to create table: %s\n"), errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(db);
		return 1;
	}

	if (!ensure_master_table(db)) {
		sqlite3_close(db);
		return 1;
	}

	if (!master_password_exists(db)) {
		if (!setup_master_password(db)) {
			sqlite3_close(db);
			return 1;
		}
	} else {
		printf(CHALK_YELLOW("Master password is already configured.\n"));
	}

	printf(CHALK_GREEN("Vault initialized: %s\n"), db_path);
	sqlite3_close(db);
	return 0;
}
