#ifndef CMD_PRIVATE_H
#define CMD_PRIVATE_H

#include <sqlite3.h>
#include "crypto_utils.h"

#define INPUT_SIZE 256
#define MIN_PASSWORD_LENGTH 1

/* Password character group flags */
#define PW_FLAG_UPPER   (1u << 0)
#define PW_FLAG_LOWER   (1u << 1)
#define PW_FLAG_DIGIT   (1u << 2)
#define PW_FLAG_SPECIAL (1u << 3)
#define PW_FLAG_ALL     (PW_FLAG_UPPER | PW_FLAG_LOWER | PW_FLAG_DIGIT | PW_FLAG_SPECIAL)

/* Database helpers */
int get_master_hash_key(sqlite3 *db, unsigned char key[MASTER_KEY_BYTES]);
int entry_exists(sqlite3 *db, const char *site);
int confirm_overwrite(const char *db_path, const char *site);

/* Password generation */
int generate_password(char *password, int length);
int generate_password_ex(char *password, int length, unsigned int flags);

#endif
