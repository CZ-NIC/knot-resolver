#include <stdio.h>
#include <errno.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include "conf_file.h"


static int step_read_file(FILE *file, char **mem)
{
	size_t mem_size, mem_used;

	mem_size = 512;
	mem_used = 0;
	*mem = malloc(mem_size);

	do {
		if (mem_used == mem_size) {
			mem_size >>= 1;
			*mem = realloc(*mem, mem_size);
		}

		mem_used += fread(*mem + mem_used, 1, mem_size - mem_used, file);
	} while (mem_used == mem_size);

	if (ferror(file)) {
		free(*mem);
		printf("Error reading from file (%s)\n", strerror(errno));
		return EXIT_FAILURE;
	} else if (!feof(file)) {
		free(*mem);
		printf("Unknown file problem\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int step_load_data(sr_session_ctx_t *sr_session, const char *file_path, int flags, struct lyd_node **data)
{
	struct ly_ctx *ly_ctx;
	char *ptr;

	ly_ctx = (struct ly_ctx *)sr_get_context(sr_session_get_connection(sr_session));

	/* parse import data */
	if (file_path) {
		*data = lyd_parse_path(ly_ctx, file_path, LYD_JSON, flags, NULL);
	} else {
		/* need to load the data into memory first */
		if (step_read_file(stdin, &ptr)) {
			return EXIT_FAILURE;
		}
		*data = lyd_parse_mem(ly_ctx, ptr, LYD_JSON, flags);
		free(ptr);
	}
	if (ly_errno) {
		printf("Data parsing failed\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}