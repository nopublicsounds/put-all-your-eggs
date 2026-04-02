#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

#define DEFAULT_DB "vault.db"

static void usage(const char *program) {
	fprintf(stderr,
			"Usage:\n"
			"  %s init [db_path]\n"
			"  %s add <site> [db_path]\n"
			"  %s get <site> [db_path]\n"
			"  %s list [db_path]\n",
			program, program, program, program);
}

static int cmd_init(const char *db_path) {
	sqlite3 *db;
	char *errmsg = NULL;
	const char *sql =
		"CREATE TABLE IF NOT EXISTS entries ("
		"  site     TEXT PRIMARY KEY,"
		"  username TEXT NOT NULL,"
		"  password TEXT NOT NULL"
		");";

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, "Failed to open DB: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		fprintf(stderr, "Failed to create table: %s\n", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(db);
		return 1;
	}

	printf("Vault initialized: %s\n", db_path);
	sqlite3_close(db);
	return 0;
}

static int cmd_add(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char username[256];
	char password[256];
	const char *sql =
		"INSERT INTO entries (site, username, password) VALUES (?, ?, ?);";

	printf("Username: ");
	if (fgets(username, sizeof(username), stdin) == NULL) return 1;
	username[strcspn(username, "\n")] = '\0';

	printf("Password: ");
	if (fgets(password, sizeof(password), stdin) == NULL) return 1;
	password[strcspn(password, "\n")] = '\0';

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, "Failed to open DB: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare SQL: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	sqlite3_bind_text(stmt, 1, site,     -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, password, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "Failed to save: %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return 1;
	}

	printf("Saved: %s\n", site);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}

static int cmd_get(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	const char *sql =
		"SELECT username, password FROM entries WHERE site = ?;";

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, "Failed to open DB: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare SQL: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	sqlite3_bind_text(stmt, 1, site, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		printf("Site    : %s\n", site);
		printf("Username: %s\n", sqlite3_column_text(stmt, 0));
		printf("Password: %s\n", sqlite3_column_text(stmt, 1));
	} else {
		printf("No entry found: %s\n", site);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}

static int cmd_list(const char *db_path) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	const char *sql = "SELECT site FROM entries ORDER BY site;";
	int count = 0;

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, "Failed to open DB: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare SQL: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		printf("%s\n", sqlite3_column_text(stmt, 0));
		count++;
	}

	if (count == 0)
		printf("(Empty)\n");

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}

int main(int argc, char **argv) {
	const char *command;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];

	if (strcmp(command, "init") == 0) {
		const char *db_path = (argc >= 3) ? argv[2] : DEFAULT_DB;
		return cmd_init(db_path);
	}

	if (strcmp(command, "add") == 0) {
		if (argc < 3 || argc > 4) {
			usage(argv[0]);
			return 1;
		}
		const char *db_path = (argc == 4) ? argv[3] : DEFAULT_DB;
		return cmd_add(db_path, argv[2]);
	}

	if (strcmp(command, "get") == 0) {
		if (argc < 3 || argc > 4) {
			usage(argv[0]);
			return 1;
		}
		const char *db_path = (argc == 4) ? argv[3] : DEFAULT_DB;
		return cmd_get(db_path, argv[2]);
	}

	if (strcmp(command, "list") == 0) {
		const char *db_path = (argc >= 3) ? argv[2] : DEFAULT_DB;
		return cmd_list(db_path);
	}

	usage(argv[0]);
	return 1;
}
