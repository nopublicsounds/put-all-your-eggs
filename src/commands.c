#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"
#include "commands.h"

#define INPUT_SIZE 256
#define MIN_PASSWORD_LENGTH 4

static const char LOWER_CHARS[] = "abcdefghijklmnopqrstuvwxyz";
static const char UPPER_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char DIGIT_CHARS[] = "0123456789";
static const char SPECIAL_CHARS[] = "!@#$%^&*()-_=+[]{};:,.?/";
static const char ALL_PASSWORD_CHARS[] =
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789"
	"!@#$%^&*()-_=+[]{};:,.?/";

static int fill_random_bytes(unsigned char *buffer, size_t size) {
	FILE *random_file = fopen("/dev/urandom", "rb");
	int ok;

	if (random_file == NULL) {
		return 0;
	}

	ok = fread(buffer, 1, size, random_file) == size;
	fclose(random_file);
	return ok;
}

static int random_index(size_t limit, size_t *out_index) {
	unsigned int value;
	unsigned int threshold;

	if (limit == 0) {
		return 0;
	}

	threshold = (unsigned int)(0xFFFFFFFFu - (0xFFFFFFFFu % limit));
	do {
		if (!fill_random_bytes((unsigned char *)&value, sizeof(value))) {
			return 0;
		}
	} while (value >= threshold);

	*out_index = (size_t)(value % limit);
	return 1;
}

static int prompt_yes_no(const char *prompt) {
	char response[16];

	printf("%s", prompt);
	fflush(stdout);

	if (!isatty(STDIN_FILENO)) {
		return 0;
	}

	if (fgets(response, sizeof(response), stdin) == NULL) {
		return 0;
	}

	return response[0] == 'y' || response[0] == 'Y';
}

static void shuffle_password(char *password, int length) {
	int index;

	for (index = length - 1; index > 0; index--) {
		size_t swap_index;
		if (!random_index((size_t)index + 1, &swap_index)) {
			continue;
		}
		char temp = password[index];
		password[index] = password[swap_index];
		password[swap_index] = temp;
	}
}

static int fill_password_group(char *password, int start, int count, const char *charset) {
	int index;
	size_t charset_length = strlen(charset);

	if (charset_length == 0) {
		return 0;
	}

	for (index = 0; index < count; index++) {
		size_t picked_index;
		if (!random_index(charset_length, &picked_index)) {
			return 0;
		}
		password[start + index] = charset[picked_index];
	}

	return 1;
}

static int generate_password(char *password, int length) {
	if (length < MIN_PASSWORD_LENGTH) {
		return 0;
	}

	password[length] = '\0';
	if (!fill_password_group(password, 0, 1, LOWER_CHARS)) return 0;
	if (!fill_password_group(password, 1, 1, UPPER_CHARS)) return 0;
	if (!fill_password_group(password, 2, 1, DIGIT_CHARS)) return 0;
	if (!fill_password_group(password, 3, 1, SPECIAL_CHARS)) return 0;
	if (!fill_password_group(password, 4, length - 4, ALL_PASSWORD_CHARS)) return 0;
	shuffle_password(password, length);
	return 1;
}

static int entry_exists(sqlite3 *db, const char *site) {
	sqlite3_stmt *stmt;
	const char *sql = "SELECT 1 FROM entries WHERE site = ? LIMIT 1;";
	int exists = 0;

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, site, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		exists = 1;
	}

	sqlite3_finalize(stmt);
	return exists;
}

static int confirm_overwrite(const char *site) {
	char prompt[INPUT_SIZE];

	snprintf(prompt, sizeof(prompt), "An entry for '%s' already exists. Overwrite it? (y/N): ", site);
	return prompt_yes_no(prompt);
}

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
	int exists;
	const char *sql =
		"INSERT INTO entries (site, username, password) VALUES (?, ?, ?) "
		"ON CONFLICT(site) DO UPDATE SET username = excluded.username, password = excluded.password;";

	if (!db_must_exist(db_path)) return 1;

	if (!read_input("Username: ", username, sizeof(username))) return 1;
	if (!read_input("Password: ", password, sizeof(password))) return 1;

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

	exists = entry_exists(db, site);
	if (exists && !confirm_overwrite(site)) {
		printf(CHALK_YELLOW("Save cancelled.\n"));
		sqlite3_close(db);
		return 0;
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

	if (exists) {
		printf(CHALK_GREEN("Updated: %s\n"), site);
	} else {
		printf(CHALK_GREEN("Saved: %s\n"), site);
	}
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
	printf(CHALK_BOLD("\nTotal %d entries\n"), count);

	if (count == 0)
		printf(CHALK_YELLOW("(Empty)\n"));

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return 0;
}

int cmd_generate(int length) {
	char *password;

	if (length < MIN_PASSWORD_LENGTH) {
		fprintf(stderr, CHALK_RED("Length must be at least %d to include all character groups.\n"), MIN_PASSWORD_LENGTH);
		return 1;
	}

	password = malloc((size_t)length + 1);
	if (password == NULL) {
		fprintf(stderr, CHALK_RED("Failed to allocate password buffer.\n"));
		return 1;
	}

	if (!generate_password(password, length)) {
		fprintf(stderr, CHALK_RED("Failed to generate password.\n"));
		free(password);
		return 1;
	}

	printf(CHALK_GREEN("Generated password: %s\n"), password);

	free(password);
	return 0;
}
