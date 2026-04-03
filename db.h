#ifndef DB_H
#define DB_H

#include <sqlite3.h>

int db_must_exist(const char *db_path);
int table_exists(sqlite3 *db, const char *table_name);
int ensure_master_table(sqlite3 *db);
int master_password_exists(sqlite3 *db);

#endif
