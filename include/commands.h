#ifndef COMMANDS_H
#define COMMANDS_H

int cmd_init(const char *db_path);
int cmd_add(const char *db_path, const char *site);
int cmd_get(const char *db_path, const char *site);
int cmd_delete(const char *db_path, const char *site);
int cmd_list(const char *db_path);
int cmd_generate(const char *db_path, int length, unsigned int flags);
int cmd_change_master(const char *db_path);
int cmd_migrate(const char *db_path);

#endif
