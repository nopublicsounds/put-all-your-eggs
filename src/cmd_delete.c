#include <stdio.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "commands.h"

int cmd_delete(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char response[16];
	const char *sql =
		"DELETE FROM entries WHERE site = ?;";

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

	printf("Are you sure you want to delete the entry for '%s'? (y/N): ", site);
	if (fgets(response, sizeof(response), stdin) == NULL) {
		sqlite3_close(db);
		return 1;
	}
	if (response[0] != 'y' && response[0] != 'Y') {
		printf(CHALK_YELLOW("Deletion cancelled.\n"));
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	sqlite3_bind_text(stmt, 1, site, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) == SQLITE_DONE) {
		if (sqlite3_changes(db) == 0) {
			fprintf(stderr, CHALK_YELLOW("No entry found to delete: %s\n"), site);
			sqlite3_finalize(stmt);
			sqlite3_close(db);
			return 1;
		}
		printf(CHALK_GREEN("Deleted entry: %s\n"), site);
	} else {
		fprintf(stderr, CHALK_RED("Failed to delete: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return 1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}
