#ifndef COMMANDS_H
#define COMMANDS_H

int cmd_init(const char *db_path);
int cmd_add(const char *db_path, const char *site);
int cmd_get(const char *db_path, const char *site);
int cmd_delete(const char *db_path, const char *site);
int cmd_list(const char *db_path);

#endif
