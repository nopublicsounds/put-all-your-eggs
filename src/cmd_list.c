#include <stdio.h>
#include <sqlite3.h>
#include "chalk.h"
#include "commands.h"

int cmd_list(const char *db_path) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	const char *sql = "SELECT site FROM entries ORDER BY site;";
	int count = 0;

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

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		printf("%s\n", sqlite3_column_text(stmt, 0));
		count++;
	}
	printf(CHALK_BOLD("\nTotal %d entries\n"), count);

	if (count == 0)
		printf(CHALK_YELLOW("(Empty)\n"));

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}
