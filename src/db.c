#include <stdio.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"

int db_must_exist(const char *db_path) {
	struct stat st;
	if (stat(db_path, &st) != 0) {
		fprintf(stderr, CHALK_YELLOW("Vault not found. Please run first: init [db_path]\n"));
		return 0;
	}
	return 1;
}

int table_exists(sqlite3 *db, const char *table_name) {
	sqlite3_stmt *stmt;
	const char *sql =
		"SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1;";
	int exists = 0;

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		exists = 1;
	}

	sqlite3_finalize(stmt);
	return exists;
}

int ensure_master_table(sqlite3 *db) {
	char *errmsg = NULL;
	const char *sql =
		"CREATE TABLE IF NOT EXISTS master_auth ("
		"  id INTEGER PRIMARY KEY CHECK (id = 1),"
		"  password TEXT NOT NULL"
		");";

	if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to create master auth table: %s\n"), errmsg);
		sqlite3_free(errmsg);
		return 0;
	}

	return 1;
}

int master_password_exists(sqlite3 *db) {
	sqlite3_stmt *stmt;
	const char *sql = "SELECT COUNT(*) FROM master_auth WHERE id = 1;";
	int count = 0;

	if (!table_exists(db, "master_auth")) {
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		count = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	return count > 0;
}
