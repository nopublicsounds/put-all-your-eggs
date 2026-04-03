#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "chalk.h"

#define DEFAULT_DB "vault.db"
#define INPUT_SIZE 256

static void usage(const char *program) {
	fprintf(stderr,
			CHALK_BOLD("Password Basket CLI\n")
			"Usage:\n"
			"  %s init " CHALK_DIM("[db_path]") "        	Initialize vault and set master password\n"
			"  %s add <site> " CHALK_DIM("[db_path]") "  	Add credentials for a site\n"
			"  %s get <site> " CHALK_DIM("[db_path]") "  	Show saved credentials for a site\n"
			"  %s delete <site> " CHALK_DIM("[db_path]") " 	Delete a site entry (with confirmation)\n"
			"  %s list " CHALK_DIM("[db_path]") "        	List all saved site names\n"
			"\n"
			"Notes:\n"
			"  - " CHALK_DIM("db_path") " is optional. Default: " CHALK_BOLD(DEFAULT_DB) "\n"
			"  - Run " CHALK_BOLD("init") " first before using other commands.\n"
			"\n"
			"Examples:\n"
			"  %s init\n"
			"  %s add github\n"
			"  %s get github\n"
			"  %s delete github\n"
			"  %s list\n",
			program, program, program, program, program,
			program, program, program, program, program);
}

static int db_must_exist(const char *db_path) {
	struct stat st;
	if (stat(db_path, &st) != 0) {
		fprintf(stderr, CHALK_YELLOW("Vault not found. Please run first: init [db_path]\n"));
		return 0;
	}
	return 1;
}

static int table_exists(sqlite3 *db, const char *table_name) {
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

static int read_input(const char *prompt, char *buffer, size_t size) {
	printf("%s", prompt);
	fflush(stdout);

	if (fgets(buffer, size, stdin) == NULL) {
		return 0;
	}

	buffer[strcspn(buffer, "\n")] = '\0';
	return buffer[0] != '\0';
}

static int ensure_master_table(sqlite3 *db) {
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

static int master_password_exists(sqlite3 *db) {
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

static int setup_master_password(sqlite3 *db) {
	sqlite3_stmt *stmt;
	char password[INPUT_SIZE];
	char confirm[INPUT_SIZE];
	const char *sql =
		"INSERT OR REPLACE INTO master_auth (id, password) VALUES (1, ?);";

	printf(CHALK_CYAN("Set a master password for this vault.\n"));

	if (!read_input("Master password: ", password, sizeof(password))) {
		fprintf(stderr, CHALK_RED("Master password is required.\n"));
		return 0;
	}

	if (!read_input("Confirm password: ", confirm, sizeof(confirm))) {
		fprintf(stderr, CHALK_RED("Password confirmation is required.\n"));
		return 0;
	}

	if (strcmp(password, confirm) != 0) {
		fprintf(stderr, CHALK_RED("Passwords do not match.\n"));
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		return 0;
	}

	sqlite3_bind_text(stmt, 1, password, -1, SQLITE_TRANSIENT);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, CHALK_RED("Failed to save master password: %s\n"), sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return 0;
	}

	sqlite3_finalize(stmt);
	printf(CHALK_GREEN("Master password set successfully.\n"));
	return 1;
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

static int cmd_add(const char *db_path, const char *site) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char username[256];
	char password[256];
	const char *sql =
		"INSERT INTO entries (site, username, password) VALUES (?, ?, ?);";

	if (!db_must_exist(db_path)) return 1;

	printf("Username: ");
	if (fgets(username, sizeof(username), stdin) == NULL) return 1;
	username[strcspn(username, "\n")] = '\0';

	printf("Password: ");
	if (fgets(password, sizeof(password), stdin) == NULL) return 1;
	password[strcspn(password, "\n")] = '\0';

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

static int cmd_get(const char *db_path, const char *site) {
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

static int cmd_delete(const char *db_path, const char *site) {
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

static int cmd_list(const char *db_path) {
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

    if (strcmp(command, "delete") == 0) {
        if (argc < 3 || argc > 4) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = (argc == 4) ? argv[3] : DEFAULT_DB;
        return cmd_delete(db_path, argv[2]);
    }

	if (strcmp(command, "list") == 0) {
		const char *db_path = (argc >= 3) ? argv[2] : DEFAULT_DB;
		return cmd_list(db_path);
	}

	usage(argv[0]);
	return 1;
}
