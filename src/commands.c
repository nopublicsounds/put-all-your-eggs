#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"
#include "commands.h"

#define INPUT_SIZE 256

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

int cmd_add(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char username[INPUT_SIZE];
	char password[INPUT_SIZE];
	const char *sql =
		"INSERT INTO entries (site, username, password) VALUES (?, ?, ?);";

	if (!db_must_exist(db_path)) return 1;

	if (!read_input("Username: ", username, sizeof(username))) return 1;
	if (!read_input("Password: ", password, sizeof(password))) return 1;

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

	sqlite3_bind_text(stmt, 1, site,     -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, password, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, CHALK_RED("Failed to save: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return 1;
	}

	printf(CHALK_GREEN("Saved: %s\n"), site);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}

int cmd_get(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
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

	sqlite3_bind_text(stmt, 1, site, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		printf("Site     : %s\n", site);
		printf("Username : %s\n", sqlite3_column_text(stmt, 0));
		printf("Password : %s\n", sqlite3_column_text(stmt, 1));
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

	if (count == 0)
		printf(CHALK_YELLOW("(Empty)\n"));

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}
