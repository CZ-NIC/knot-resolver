#include <errno.h>
#include <string.h>

#include "contrib/dynarray.h"
#include "process.h"
#include "commands.h"


static const cmd_desc_t *get_cmd_desc(const char *command)
{
	/* Try to find requested command in buid-in commands. */
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL) {
		if (strcmp(desc->name, command) == 0) {
			break;
		}
		desc++;
	}

	/* Try to find requested command in created commands. */
	dynarray_foreach(cmd, cmd_desc_t *, i, dyn_cmd_table) {
		cmd_desc_t *dyn_desc = *i;
		if (strcmp(dyn_desc->name, command) == 0) {
			desc = dyn_desc;
			break;
		}
	}

	if (desc->name == NULL) {
		printf("invalid command '%s'\n", command);
		return NULL;
	}

	return desc;
}

int process_cmd(int argc, const char **argv, params_t *params)
{
	if (argc == 0) {
		return ENOTSUP;
	}

	/* Check the command name. */
	const cmd_desc_t *desc = get_cmd_desc(argv[0]);
	if (desc == NULL) {
		return ENOENT;
	}

	/* Check for program exit. */
	if (desc->fcn == NULL) {
		return CLI_EXIT;
	}

	/* Prepare command arguments. */
	cmd_args_t args = {
		.desc = desc,
		.argc = argc - 1,
		.argv = argv + 1,
		.timeout = params->timeout,
	};

	/* Execute the command. */
	int ret = desc->fcn(&args);

	return ret;
}