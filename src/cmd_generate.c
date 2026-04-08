#include <stdio.h>
#include <stdlib.h>
#include "chalk.h"
#include "cmd_private.h"
#include "commands.h"

int cmd_generate(int length) {
	char *password;

	if (length < MIN_PASSWORD_LENGTH) {
		fprintf(stderr, CHALK_RED("Length must be at least %d to include all character groups.\n"), MIN_PASSWORD_LENGTH);
		return 1;
	}

	password = malloc((size_t)length + 1);
	if (password == NULL) {
		fprintf(stderr, CHALK_RED("Failed to allocate password buffer.\n"));
		return 1;
	}

	if (!generate_password(password, length)) {
		fprintf(stderr, CHALK_RED("Failed to generate password.\n"));
		free(password);
		return 1;
	}

	printf(CHALK_GREEN("Generated password: %s\n"), password);

	free(password);
	return 0;
}
