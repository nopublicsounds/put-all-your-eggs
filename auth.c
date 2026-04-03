#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sqlite3.h>
#include "chalk.h"
#include "db.h"
#include "auth.h"

#define INPUT_SIZE 256

int read_input(const char *prompt, char *buffer, size_t size) {
	printf("%s", prompt);
	fflush(stdout);

	if (fgets(buffer, size, stdin) == NULL) {
		return 0;
	}

	buffer[strcspn(buffer, "\n")] = '\0';
	return buffer[0] != '\0';
}

int read_secret(const char *prompt, char *buffer, size_t size) {
	struct termios old, new;
	int ok;

	printf("%s", prompt);
	fflush(stdout);

	tcgetattr(STDIN_FILENO, &old);
	new = old;
	new.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

	ok = (fgets(buffer, size, stdin) != NULL);

	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	printf("\n");

	if (!ok) return 0;
	buffer[strcspn(buffer, "\n")] = '\0';
	return buffer[0] != '\0';
}

int setup_master_password(sqlite3 *db) {
	sqlite3_stmt *stmt;
	char password[INPUT_SIZE];
	char confirm[INPUT_SIZE];
	const char *sql =
		"INSERT OR REPLACE INTO master_auth (id, password) VALUES (1, ?);";

	printf(CHALK_CYAN("Set a master password for this vault.\n"));

	if (!read_secret("Master password: ", password, sizeof(password))) {
		fprintf(stderr, CHALK_RED("Master password is required.\n"));
		return 0;
	}

	if (!read_secret("Confirm password: ", confirm, sizeof(confirm))) {
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

int authenticate_master(const char *db_path) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char input[INPUT_SIZE];
	const char *sql = "SELECT password FROM master_auth WHERE id = 1;";
	int authenticated = 0;

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to open DB: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, CHALK_RED("Failed to prepare SQL: %s\n"), sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *stored_password = (const char *)sqlite3_column_text(stmt, 0);

		if (!read_secret("Enter master password: ", input, sizeof(input))) {
			sqlite3_finalize(stmt);
			sqlite3_close(db);
			return 0;
		}

		if (strcmp(input, stored_password) == 0) {
			authenticated = 1;
		} else {
			fprintf(stderr, CHALK_RED("Authentication failed.\n"));
		}
	} else {
		fprintf(stderr, CHALK_YELLOW("No master password set. Run init first.\n"));
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return authenticated;
}
