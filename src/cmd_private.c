#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include "chalk.h"
#include "cmd_private.h"
#include "auth.h"

static const char LOWER_CHARS[] = "abcdefghijklmnopqrstuvwxyz";
static const char UPPER_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char DIGIT_CHARS[] = "0123456789";
static const char SPECIAL_CHARS[] = "!@#$%^&*()-_=+[]{};:,.?/";

int get_master_hash_key(sqlite3 *db, unsigned char key[MASTER_KEY_BYTES]) {
	sqlite3_stmt *stmt;
	const char *stored;
	const char *sql = "SELECT password FROM master_auth WHERE id = 1;";
	int ok = 0;

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		stored = (const char *)sqlite3_column_text(stmt, 0);
		if (stored != NULL) {
			ok = derive_key_from_stored_hash(stored, key);
		}
	}

	sqlite3_finalize(stmt);
	return ok;
}

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

int generate_password(char *password, int length) {
	return generate_password_ex(password, length, PW_FLAG_ALL);
}

int generate_password_ex(char *password, int length, unsigned int flags) {
	int pos = 0;
	int n_groups = 0;
	char combined[256];
	size_t combined_len = 0;

	/* Count active groups and build combined charset */
	if (flags & PW_FLAG_LOWER) {
		n_groups++;
		size_t len = strlen(LOWER_CHARS);
		memcpy(combined + combined_len, LOWER_CHARS, len);
		combined_len += len;
	}
	if (flags & PW_FLAG_UPPER) {
		n_groups++;
		size_t len = strlen(UPPER_CHARS);
		memcpy(combined + combined_len, UPPER_CHARS, len);
		combined_len += len;
	}
	if (flags & PW_FLAG_DIGIT) {
		n_groups++;
		size_t len = strlen(DIGIT_CHARS);
		memcpy(combined + combined_len, DIGIT_CHARS, len);
		combined_len += len;
	}
	if (flags & PW_FLAG_SPECIAL) {
		n_groups++;
		size_t len = strlen(SPECIAL_CHARS);
		memcpy(combined + combined_len, SPECIAL_CHARS, len);
		combined_len += len;
	}
	combined[combined_len] = '\0';

	if (n_groups == 0 || combined_len == 0) {
		return 0;
	}

	/* length must be at least one per active group */
	if (length < n_groups) {
		return 0;
	}

	/* Guarantee at least 1 char from each active group */
	if (flags & PW_FLAG_LOWER) {
		if (!fill_password_group(password, pos, 1, LOWER_CHARS)) return 0;
		pos++;
	}
	if (flags & PW_FLAG_UPPER) {
		if (!fill_password_group(password, pos, 1, UPPER_CHARS)) return 0;
		pos++;
	}
	if (flags & PW_FLAG_DIGIT) {
		if (!fill_password_group(password, pos, 1, DIGIT_CHARS)) return 0;
		pos++;
	}
	if (flags & PW_FLAG_SPECIAL) {
		if (!fill_password_group(password, pos, 1, SPECIAL_CHARS)) return 0;
		pos++;
	}

	/* Fill remaining positions from combined charset */
	if (!fill_password_group(password, pos, length - pos, combined)) return 0;
	password[length] = '\0';
	shuffle_password(password, length);
	return 1;
}

int entry_exists(sqlite3 *db, const char *site) {
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

int prompt_yes_no(const char *prompt) {
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

static int clipboard_command(const char *cmd, const char *text) {
	FILE *pipe = popen(cmd, "w");
	if (pipe == NULL) {
		return 0;
	}

	if (fputs(text, pipe) == EOF) {
		pclose(pipe);
		return 0;
	}

	return pclose(pipe) == 0;
}

int copy_to_clipboard(const char *text) {
	static const char *commands[] = {
		"xclip -selection clipboard",
		"xsel --clipboard --input",
		"wl-copy"
	};

	for (size_t index = 0; index < sizeof(commands) / sizeof(commands[0]); ++index) {
		if (clipboard_command(commands[index], text)) {
			return 1;
		}
	}

	return 0;
}

int confirm_overwrite(const char *db_path, const char *site) {
	char prompt[INPUT_SIZE];

	snprintf(prompt, sizeof(prompt), "An entry for '%s' already exists. Overwrite it? (y/N): ", site);
	if (!prompt_yes_no(prompt)) {
		return 0;
	}

	if (!authenticate_master(db_path)) {
		return 0;
	}

	return 1;
}
