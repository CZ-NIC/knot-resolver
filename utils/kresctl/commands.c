#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include "lib/generic/array.h"
#include "modules/sysrepo/common/sysrepo.h"
#include "commands.h"
#include "process.h"

/* Build-in commands */
#define CMD_EXIT        "exit"
#define CMD_HELP        "help"
#define CMD_VERSION     "version"
#define CMD_IMPORT      "import"
#define CMD_EXPORT      "export"
#define CMD_BEGIN       "begin"
#define CMD_COMMIT      "commit"
#define CMD_ABORT       "abort"
#define CMD_VALIDATE    "validate"
#define CMD_DIFF        "diff"
#define CMD_PERSIST     "persist"


static int cmd_import(cmd_args_t *args)
{
	struct lyd_node *data;
	sr_session_ctx_t *sr_session = NULL;
	const char *file_path = args->argv[0];
	int flags = LYD_OPT_CONFIG | LYD_OPT_TRUSTED | LYD_OPT_STRICT;

	// int ret = sr_session_start(sysrepo_ctx->connection, SR_DS_RUNNING, &sr_session);
	// if (ret) {
	// 	printf("failed to start sysrepo session, %s\n", sr_strerror(ret));
	// 	return CLI_ECMD;
	// }

	// if (!ret) ret = step_load_data(sr_session, file_path, flags, &data);


	// /* replace config (always spends data) */
	// ret = sr_replace_config(sr_session, YM_COMMON, data, 0, 0);
	// if (ret) {
	// 	printf("failed to replace configuration, %s\n", sr_strerror(ret));
	// 	return CLI_ECMD;
	// }

	// ret = sr_session_stop(sr_session);
	// if (ret) {
	// 	printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
	// 	return CLI_ECMD;
	// }

	return CLI_EOK;
}

static int cmd_export(cmd_args_t *args)
{
	char *xpath;
	struct lyd_node *data;
	sr_session_ctx_t *sr_session = NULL;
	FILE *file = NULL;

	/* If argument, open file for writting */
	if (args->argc == 1) {
		file = fopen(args->argv[0], "w");
		if (!file) {
			printf("Failed to open \"%s\" for writing (%s)", args->argv[0], strerror(errno));
			return CLI_ECMD;
		}
	}

	asprintf(&xpath, "/%s:*", YM_COMMON);
	int ret = sr_session_start(sysrepo_ctx->connection, SR_DS_RUNNING, &sr_session);
	if (!ret) ret = sr_get_data(sr_session, xpath, 0, 0, 0, &data);
	if (ret) {
		printf("failed to get configuration from sysrepo, %s\n", sr_strerror(ret));
		free(xpath);
		return CLI_ECMD;
	}

	ret = sr_session_stop(sr_session);
	if (ret) {
		printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	/* print exported data to file or stdout */
	lyd_print_file(file ? file : stdout, data, LYD_JSON, LYP_FORMAT | LYP_WITHSIBLINGS);
	lyd_free_withsiblings(data);
	free(xpath);

	return CLI_EOK;
}

static int cmd_begin(cmd_args_t *args)
{
	sr_session_ctx_t *sr_session = NULL;

	if (sysrepo_ctx->session) {
		printf("transaction has already begin\n");
		return CLI_ECMD;
	}

	int ret = sr_session_start(sysrepo_ctx->connection, SR_DS_CANDIDATE, &sr_session);
	if (ret) {
		printf("failed to start sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	ret = sr_lock(sr_session, YM_COMMON);
	if (ret) {
		printf("failed to lock candidate datastore, %s\n", sr_strerror(ret));
		sr_session_stop(sr_session);
		return CLI_ECMD;
	}
	sysrepo_ctx->session = sr_session;

	return CLI_EOK;
}

static int cmd_commmit(cmd_args_t *args)
{
	if (!sysrepo_ctx->session){
		printf("no active transaction\n");
		return CLI_ECMD;
	}

	int ret = sr_validate(sysrepo_ctx->session, YM_COMMON, 0);
	if (ret) {
		printf("validation failed, %s\n", sr_strerror(ret));
	}

	/* switch datastore to RUNNING */
	ret = sr_session_switch_ds(sysrepo_ctx->session, SR_DS_RUNNING);
	/* copy configuration from CANDIDATE to RUNNING datastore */
	if (!ret) ret = sr_copy_config(sysrepo_ctx->session, YM_COMMON,
	                               SR_DS_CANDIDATE, args->timeout, 0);
	if (ret) {
		printf("commit failed, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	ret = sr_session_stop(sysrepo_ctx->session);
	if (ret) {
		printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}
	sysrepo_ctx->session = NULL;

	return CLI_EOK;
}

static int cmd_abort(cmd_args_t *args)
{
	if (!sysrepo_ctx->session){
		printf("no active transaction\n");
		return 1;
	}

	int ret = sr_session_stop(sysrepo_ctx->session);
	if (ret) {
		printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}
	sysrepo_ctx->session = NULL;

	return CLI_EOK;
}

static int cmd_validate(cmd_args_t *args)
{
	if (!sysrepo_ctx->session){
		printf("no active transaction\n");
		return CLI_ECMD;
	}

	int ret = sr_validate(sysrepo_ctx->session, YM_COMMON, args->timeout);
	if (ret) {
		printf("validation failed, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}
	return CLI_EOK;
}

static int cmd_diff(cmd_args_t *args)
{
	return CLI_EOK;
}

static int cmd_persist(cmd_args_t *args)
{
	sr_session_ctx_t *sr_session = NULL;

	int ret = sr_session_start(sysrepo_ctx->connection, SR_DS_STARTUP, &sr_session);
	if (ret) {
		printf("failed to start sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	/* copy configuration from RUNNING to STARTUP datastore */
	if (!ret) ret = sr_copy_config(sr_session, YM_COMMON, SR_DS_RUNNING, 0, 0);
	if (ret) {
		printf("commit failed, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	ret = sr_session_stop(sr_session);
	if (ret) {
		printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	return CLI_EOK;
}

/* Funtcions for dynamic commands */

static int cmd_leaf(cmd_args_t *args)
{
	int ret = CLI_EOK;
	const char *path = args->desc->xpath;

	/* get operational data */
	if (!args->argc) {

		char *strval;
		sr_val_t *val = NULL;
		sr_session_ctx_t *sr_session = NULL;

		if (!ret) ret = sr_session_start(sysrepo_ctx->connection, SR_DS_OPERATIONAL, &sr_session);
		if (!ret) ret = sr_get_item(sr_session, path, args->timeout, &val);
		if (ret) {
			printf("get configuration data failed, %s\n", sr_strerror(ret));
			sr_session_stop(sr_session);
			return CLI_ECMD;
		}

		valtostr(val, &strval);
		printf("%s = %s\n", args->desc->name, strval);

		sr_session_stop(sr_session);
		sr_free_val(val);
		free(strval);

	}
	/* set configuration data */
	else if (args->argc == 1) {
		/* check if there is active session */
		if (!sysrepo_ctx->session) {
			printf("no active transaction\n");
			return CLI_ECMD;
		}

		if (!ret) ret = sr_session_switch_ds(sysrepo_ctx->session,SR_DS_CANDIDATE);
		if (!ret) ret = sr_set_item_str(sysrepo_ctx->session, path, args->argv[0], NULL, 0);
		if (!ret) ret = sr_apply_changes(sysrepo_ctx->session, 0, 0);
		if (ret) {
			printf("set data value failed, %s\n", sr_strerror(ret));
			return CLI_ECMD;
		}
	}
	else {
		printf("too many arguments\n");
		return CLI_ECMD;
	}

	return CLI_EOK;
}

static int cmd_container(cmd_args_t *args)
{
	int ret = CLI_EOK;
	const char *path = args->desc->xpath;

	/* get operational data */
	if (!args->argc) {

		char *xpath;
		struct lyd_node *data = NULL;
		sr_session_ctx_t *sr_session = NULL;

		asprintf(&xpath, "%s/*//.", args->desc->xpath);
		if (!ret) ret = sr_session_start(sysrepo_ctx->connection, SR_DS_RUNNING, &sr_session);
		if (!ret) ret = sr_get_data(sr_session, xpath, 0, args->timeout, 0, &data);
		if (ret) {
			printf("get configuration data failed, %s\n", sr_strerror(ret));
			sr_session_stop(sr_session);
			return CLI_ECMD;
		}

		lyd_print_file(stdout, data, LYD_JSON, LYP_FORMAT | LYP_WITHSIBLINGS);

		lyd_free_withsiblings(data);
		sr_session_stop(sr_session);
		free(xpath);
	}
	else {
		printf("too many arguments\n");
		return CLI_ECMD;
	}

	return CLI_EOK;
}

static int cmd_list(cmd_args_t *args)
{
	return CLI_EOK;
}

static int cmd_leaflist(cmd_args_t *args)
{
	return CLI_EOK;
}

static void cmd_dynarray_deep_free(cmd_dynarray_t * d)
{
	dynarray_foreach(cmd, cmd_desc_t *, i, *d) {
		free(*i);
	}
	cmd_dynarray_free(d);
}

cmd_dynarray_t dyn_cmd_table;

const cmd_desc_t cmd_table[] = {
	/* name, function, flags, xpath, */
	{ CMD_EXIT,     NULL,           NULL, CMD_FNONE },
	{ CMD_HELP,     print_commands, NULL, CMD_FNONE },
	{ CMD_VERSION,  print_version,  NULL, CMD_FNONE },
	/* Configuration file */
	{ CMD_IMPORT,   cmd_import,     NULL, CMD_FNONE },
	{ CMD_EXPORT,   cmd_export,     NULL, CMD_FNONE },
	/* Transaction */
	{ CMD_BEGIN,    cmd_begin,      NULL, CMD_FINTER },
	{ CMD_COMMIT,   cmd_commmit,    NULL, CMD_FINTER },
	{ CMD_ABORT,    cmd_abort,      NULL, CMD_FINTER },
	{ CMD_VALIDATE, cmd_validate,   NULL, CMD_FINTER },
	{ CMD_DIFF,     cmd_diff,       NULL, CMD_FINTER },
	{ CMD_PERSIST,  cmd_persist,    NULL, CMD_FNONE },
	/*  */
	{ NULL }
};

dynarray_declare(cmd_help, cmd_help_t *, DYNARRAY_VISIBILITY_STATIC, 0)
    dynarray_define(cmd_help, cmd_help_t *, DYNARRAY_VISIBILITY_STATIC)
static void cmd_help_dynarray_deep_free(cmd_help_dynarray_t * d)
{
	dynarray_foreach(cmd_help, cmd_help_t *, i, *d) {
		free(*i);
	}
	cmd_help_dynarray_free(d);
}

cmd_help_dynarray_t dyn_cmd_help_table;

static const cmd_help_t cmd_help_table[] = {
	/* name, arguments, description */
	{ CMD_EXIT,     "",            "Exit the program." },
	{ CMD_HELP,     "",            "Print the program help." },
	{ CMD_VERSION,  "",            "Print the program version." },
	{ "", "", "" },
	{ CMD_IMPORT,   "<file-path>", "Import YAML configuration file." },
	{ CMD_EXPORT,   "<file-path>", "Export YAML configuration file." },
	{ "", "", "" },
	{ CMD_BEGIN,    "",            "Begin a transaction." },
	{ CMD_COMMIT,   "",            "Commit a transaction." },
	{ CMD_ABORT,    "",            "Abort a transaction." },
	{ CMD_VALIDATE, "",            "Validate a transaction changes." },
	{ CMD_DIFF,     "",            "Show configuration changes." },
	{ CMD_PERSIST,  "",            "Make running configuration persist during system reboots." },
	{ NULL }
};

int create_cmd_table(sr_conn_ctx_t *sr_connection)
{
	int ret = CLI_EOK;
	const char *path = NULL;
	struct lys_node *root = NULL, *last = NULL;
	struct ly_ctx *ly_context = NULL;

	ly_context = sr_get_context(sr_connection);
	assert(ly_context != NULL);

	cmd_help_t *cmd_help = malloc(sizeof(cmd_help_t));
	cmd_help->name = "server";
	cmd_help->params = "";
	cmd_help->desc = "Parameters of the DNS resolver system.";

	cmd_desc_t *cmd = malloc(sizeof(cmd_desc_t));
	cmd->name = "server";
	cmd->fcn = &cmd_container;
	cmd->xpath = "/"YM_COMMON":dns-resolver/server";
	cmd->flags = CMD_FSTATE;

	cmd_help_dynarray_add(&dyn_cmd_help_table, &cmd_help);

	cmd_dynarray_add(&dyn_cmd_table, &cmd);

	return CLI_EOK;
}

void destroy_cmd_table()
{
	cmd_dynarray_deep_free(&dyn_cmd_table);
	cmd_help_dynarray_deep_free(&dyn_cmd_help_table);
}

int print_version(cmd_args_t *args)
{
	printf("%s (%s), version %s\n", PROGRAM_NAME, PROJECT_NAME, PACKAGE_VERSION);
}

int print_commands(cmd_args_t *args)
{
	printf("\nCommands:\n");

	/* Print all build-in commands */
	for (const cmd_help_t *cmd = cmd_help_table; cmd->name != NULL; cmd++) {
		printf(" %-15s %-15s %s\n", cmd->name, cmd->params, cmd->desc);
	}
	printf("\n");

	/* Print all created commands */
	dynarray_foreach(cmd_help, cmd_help_t *, i, dyn_cmd_help_table) {
		cmd_help_t *cmd = *i;
		printf(" %-15s %-15s %s\n", cmd->name, cmd->params, cmd->desc);
	}

	printf("\n"
	       "Note:\n"
	       "");
}
