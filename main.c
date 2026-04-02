#include <stdio.h>
#include <string.h>

static void usage(const char *program) {
	fprintf(stderr,
			"Usage:\n"
			"  %s init [db_path]\n"
			"  %s add <site> [db_path]\n"
			"  %s get <site> [db_path]\n"
			"  %s list [db_path]\n",
			program, program, program, program);
}

int main(int argc, char **argv) {
	const char *command;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];

	if (strcmp(command, "init") == 0) {
		puts("[STEP 1] init command selected");
		return 0;
	}

	if (strcmp(command, "add") == 0) {
		puts("[STEP 1] add command selected");
		return 0;
	}

	if (strcmp(command, "get") == 0) {
		puts("[STEP 1] get command selected");
		return 0;
	}

	if (strcmp(command, "list") == 0) {
		puts("[STEP 1] list command selected");
		return 0;
	}

	usage(argv[0]);
	return 1;
}
