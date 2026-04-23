#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "chalk.h"
#include "auth.h"
#include "cmd_private.h"
#include "commands.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_DB "vault.db"
#define ENV_DB_PATH "PWMGR_DB_PATH"
#define CONFIG_KEY_DB "default_db="

static int make_absolute_path(const char *input, char *output, size_t output_size) {
    char cwd[PATH_MAX];

    if (input == NULL || input[0] == '\0') {
        return 0;
    }

    if (input[0] == '/') {
        if (snprintf(output, output_size, "%s", input) >= (int)output_size) {
            return 0;
        }
        return 1;
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        return 0;
    }

    if (snprintf(output, output_size, "%s/%s", cwd, input) >= (int)output_size) {
        return 0;
    }

    return 1;
}

static int ensure_dir(const char *path) {
    if (mkdir(path, 0700) == 0) {
        return 1;
    }

    if (errno == EEXIST) {
        return 1;
    }

    return 0;
}

static int get_config_path(char *output, size_t output_size) {
    const char *xdg_config_home = getenv("XDG_CONFIG_HOME");
    const char *home;

    if (xdg_config_home != NULL && xdg_config_home[0] != '\0') {
        if (snprintf(output, output_size, "%s/pwmgr/config", xdg_config_home) >= (int)output_size) {
            return 0;
        }
        return 1;
    }

    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return 0;
    }

    if (snprintf(output, output_size, "%s/.config/pwmgr/config", home) >= (int)output_size) {
        return 0;
    }

    return 1;
}

static int ensure_config_dirs(void) {
    const char *xdg_config_home = getenv("XDG_CONFIG_HOME");
    const char *home;
    char config_root[PATH_MAX];
    char pwmgr_dir[PATH_MAX];

    if (xdg_config_home != NULL && xdg_config_home[0] != '\0') {
        if (snprintf(config_root, sizeof(config_root), "%s", xdg_config_home) >= (int)sizeof(config_root)) {
            return 0;
        }
    } else {
        home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            return 0;
        }
        if (snprintf(config_root, sizeof(config_root), "%s/.config", home) >= (int)sizeof(config_root)) {
            return 0;
        }
    }

    if (snprintf(pwmgr_dir, sizeof(pwmgr_dir), "%s/pwmgr", config_root) >= (int)sizeof(pwmgr_dir)) {
        return 0;
    }

    if (!ensure_dir(config_root)) {
        return 0;
    }

    if (!ensure_dir(pwmgr_dir)) {
        return 0;
    }

    return 1;
}

static int read_config_db(char *output, size_t output_size) {
    char config_path[PATH_MAX];
    FILE *file;
    char line[PATH_MAX + 64];

    if (!get_config_path(config_path, sizeof(config_path))) {
        return 0;
    }

    file = fopen(config_path, "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        size_t key_len = strlen(CONFIG_KEY_DB);
        size_t value_len;

        if (strncmp(line, CONFIG_KEY_DB, key_len) != 0) {
            continue;
        }

        value_len = strlen(line + key_len);
        while (value_len > 0 && ((line + key_len)[value_len - 1] == '\n' || (line + key_len)[value_len - 1] == '\r')) {
            (line + key_len)[value_len - 1] = '\0';
            value_len--;
        }

        if (value_len == 0) {
            fclose(file);
            return 0;
        }

        if (snprintf(output, output_size, "%s", line + key_len) >= (int)output_size) {
            fclose(file);
            return 0;
        }

        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}

static int write_config_db(const char *db_path) {
    char config_path[PATH_MAX];
    char abs_path[PATH_MAX];
    FILE *file;

    if (!make_absolute_path(db_path, abs_path, sizeof(abs_path))) {
        return 0;
    }

    if (!ensure_config_dirs()) {
        return 0;
    }

    if (!get_config_path(config_path, sizeof(config_path))) {
        return 0;
    }

    file = fopen(config_path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "%s%s\n", CONFIG_KEY_DB, abs_path);
    fclose(file);
    return 1;
}

static const char *resolve_db_path(const char *cli_db_path, char *buffer, size_t buffer_size) {
    const char *env_db_path;

    if (cli_db_path != NULL && cli_db_path[0] != '\0') {
        return cli_db_path;
    }

    env_db_path = getenv(ENV_DB_PATH);
    if (env_db_path != NULL && env_db_path[0] != '\0') {
        return env_db_path;
    }

    if (read_config_db(buffer, buffer_size)) {
        return buffer;
    }

    return DEFAULT_DB;
}

static int cmd_config(int argc, char **argv) {
    char db_buf[PATH_MAX];

    if (argc == 4 && strcmp(argv[2], "get") == 0 && strcmp(argv[3], "db") == 0) {
        const char *resolved = resolve_db_path(NULL, db_buf, sizeof(db_buf));
        printf("%s\n", resolved);
        return 0;
    }

    if (argc == 5 && strcmp(argv[2], "set") == 0 && strcmp(argv[3], "db") == 0) {
        if (!write_config_db(argv[4])) {
            fprintf(stderr, CHALK_RED("Failed to save config.\n"));
            return 1;
        }

        if (!make_absolute_path(argv[4], db_buf, sizeof(db_buf))) {
            fprintf(stderr, CHALK_RED("Invalid DB path.\n"));
            return 1;
        }

        printf("Default DB set to: %s\n", db_buf);
        return 0;
    }

    fprintf(stderr,
            "Usage:\n"
            "  %s config get db\n"
            "  %s config set db <path>\n",
            argv[0], argv[0]);
    return 1;
}

static void usage(const char *program) {
    fprintf(stderr,
            CHALK_BOLD("Password Basket CLI\n")
            "Usage:\n"
            "  %s init " CHALK_DIM("[db_path]") "         Initialize vault and set master password\n"
            "  %s add <site> " CHALK_DIM("[db_path]") "   Add credentials for a site\n"
            "  %s get <site> " CHALK_DIM("[db_path]") "   Show saved credentials for a site\n"
            "  %s delete <site> " CHALK_DIM("[db_path]") " Delete a site entry (with confirmation)\n"
            "  %s list " CHALK_DIM("[db_path]") "         List all saved site names\n"
            "  %s generate <length> " CHALK_DIM("[options]") "         Generate a random password\n"
            "       " CHALK_DIM("--digits   ") "  Digits only (0-9)\n"
            "       " CHALK_DIM("--alpha    ") "  Letters only (upper + lower)\n"
            "       " CHALK_DIM("--lowercase") "  Lowercase letters only\n"
            "  %s change-master " CHALK_DIM("[db_path]") " Change master password\n"
            "  %s migrate " CHALK_DIM("[db_path]") "      Encrypt legacy/plain passwords\n"
            "  %s config get db                Show effective default DB path\n"
            "  %s config set db <path>         Set default DB path\n"
            "\n"
            "Notes:\n"
            "  - " CHALK_DIM("db_path") " is optional. Priority: CLI arg > " CHALK_BOLD(ENV_DB_PATH) " > config > " CHALK_BOLD(DEFAULT_DB) "\n"
            "  - Run " CHALK_BOLD("init") " first before using other commands.\n"
            "\n"
            "Examples:\n"
            "  %s init\n"
            "  %s add github\n"
            "  %s get github\n"
            "  %s delete github\n"
            "  %s list\n"
            "  %s generate 20\n"
            "  %s change-master\n"
            "  %s migrate\n"
            "  %s config set db ~/vaults/work.db\n"
            "  %s config get db\n",
            program, program, program, program, program, program, program, program, program, program,
            program, program, program, program, program, program, program, program, program, program);
}

int main(int argc, char **argv) {
    const char *command;
    char db_from_config[PATH_MAX];

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    command = argv[1];

    if (strcmp(command, "config") == 0) {
        return cmd_config(argc, argv);
    }

    if (strcmp(command, "init") == 0) {
        if (argc > 3) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = resolve_db_path((argc >= 3) ? argv[2] : NULL, db_from_config, sizeof(db_from_config));
        return cmd_init(db_path);
    }

    if (strcmp(command, "add") == 0) {
        if (argc < 3 || argc > 4) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = resolve_db_path((argc == 4) ? argv[3] : NULL, db_from_config, sizeof(db_from_config));
        return cmd_add(db_path, argv[2]);
    }

    if (strcmp(command, "get") == 0) {
        if (argc < 3 || argc > 4) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = resolve_db_path((argc == 4) ? argv[3] : NULL, db_from_config, sizeof(db_from_config));
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
        const char *db_path = resolve_db_path((argc == 4) ? argv[3] : NULL, db_from_config, sizeof(db_from_config));
        if (!authenticate_master(db_path)) {
            return 1;
        }
        return cmd_delete(db_path, argv[2]);
    }

    if (strcmp(command, "list") == 0) {
        if (argc > 3) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = resolve_db_path((argc >= 3) ? argv[2] : NULL, db_from_config, sizeof(db_from_config));
        return cmd_list(db_path);
    }

    if (strcmp(command, "generate") == 0) {
        char *endptr;
        long length;
        const char *db_path = NULL;
        unsigned int flags = 0;
        int has_lowercase = 0;
        int has_other = 0;
        int i;

        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }

        length = strtol(argv[2], &endptr, 10);
        if (*argv[2] == '\0' || *endptr != '\0' || length <= 0 || length > 1024) {
            fprintf(stderr, CHALK_RED("Length must be an integer between 1 and 1024.\n"));
            return 1;
        }

        for (i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--digits") == 0) {
                flags |= PW_FLAG_DIGIT;
                has_other = 1;
            } else if (strcmp(argv[i], "--alpha") == 0) {
                flags |= PW_FLAG_UPPER | PW_FLAG_LOWER;
                has_other = 1;
            } else if (strcmp(argv[i], "--lowercase") == 0) {
                flags |= PW_FLAG_LOWER;
                has_lowercase = 1;
            } else if (argv[i][0] == '-') {
                fprintf(stderr, CHALK_RED("Unknown option: %s\n"), argv[i]);
                fprintf(stderr, "Available options: --digits, --alpha, --lowercase\n");
                return 1;
            } else {
                if (db_path != NULL) {
                    usage(argv[0]);
                    return 1;
                }
                db_path = argv[i];
            }
        }

        /* --lowercase strips uppercase from whatever was selected */
        if (has_lowercase) {
            flags &= ~PW_FLAG_UPPER;
        }

        if (flags == 0) {
            flags = PW_FLAG_ALL;
        }

        db_path = resolve_db_path(db_path, db_from_config, sizeof(db_from_config));
        return cmd_generate(db_path, (int)length, flags);
    }

    if (strcmp(command, "change-master") == 0) {
        if (argc > 3) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = resolve_db_path((argc >= 3) ? argv[2] : NULL, db_from_config, sizeof(db_from_config));
        if (!authenticate_master(db_path)) {
            return 1;
        }
        return cmd_change_master(db_path);
    }

    if (strcmp(command, "migrate") == 0) {
        if (argc > 3) {
            usage(argv[0]);
            return 1;
        }
        const char *db_path = resolve_db_path((argc >= 3) ? argv[2] : NULL, db_from_config, sizeof(db_from_config));
        if (!authenticate_master(db_path)) {
            return 1;
        }
        return cmd_migrate(db_path);
    }

    usage(argv[0]);
    return 1;
}