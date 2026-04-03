#include <stdio.h>
#include <string.h>
#include "chalk.h"
#include "auth.h"
#include "commands.h"

#define DEFAULT_DB "vault.db"

static void usage(const char *program) {
    fprintf(stderr,
            CHALK_BOLD("Password Basket CLI\n")
            "Usage:\n"
            "  %s init " CHALK_DIM("[db_path]") "         Initialize vault and set master password\n"
            "  %s add <site> " CHALK_DIM("[db_path]") "   Add credentials for a site\n"
            "  %s get <site> " CHALK_DIM("[db_path]") "   Show saved credentials for a site\n"
            "  %s delete <site> " CHALK_DIM("[db_path]") " Delete a site entry (with confirmation)\n"
            "  %s list " CHALK_DIM("[db_path]") "         List all saved site names\n"
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
        if (!authenticate_master(db_path)) {
            return 1;
        }
        return cmd_get(db_path, argv[2]);
    }

    if (strcmp(command, "delete") == 0) {
        if (argc < 3 || argc > 4) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = (argc == 4) ? argv[3] : DEFAULT_DB;
        if (!authenticate_master(db_path)) {
            return 1;
        }
        return cmd_delete(db_path, argv[2]);
    }

    if (strcmp(command, "list") == 0) {
        const char *db_path = (argc >= 3) ? argv[2] : DEFAULT_DB;
        return cmd_list(db_path);
    }

    usage(argv[0]);
    return 1;
}