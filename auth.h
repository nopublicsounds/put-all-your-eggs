#ifndef AUTH_H
#define AUTH_H

#include <sqlite3.h>
#include <stddef.h>

int read_input(const char *prompt, char *buffer, size_t size);
int setup_master_password(sqlite3 *db);
int authenticate_master(const char *db_path);

#endif
