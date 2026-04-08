#ifndef CMD_PRIVATE_H
#define CMD_PRIVATE_H

#include <sqlite3.h>
#include "crypto_utils.h"

#define INPUT_SIZE 256
#define MIN_PASSWORD_LENGTH 4

/* Database helpers */
int get_master_hash_key(sqlite3 *db, unsigned char key[MASTER_KEY_BYTES]);
int entry_exists(sqlite3 *db, const char *site);
int confirm_overwrite(const char *db_path, const char *site);

/* Password generation */
int generate_password(char *password, int length);

#endif
