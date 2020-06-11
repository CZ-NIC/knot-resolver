#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include "lib/generic/array.h"
#include "modules/sysrepo/common/string_helper.h"
#include "modules/sysrepo/common/sysrepo.h"
#include "commands.h"
#include "process.h"
#include "conf_file.h"

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

	int ret = sr_session_start(sysrepo_ctx->connection, SR_DS_RUNNING, &sr_session);
	if (ret) {
		printf("failed to start sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	if (!ret) ret = step_load_data(sr_session, file_path, flags, &data);


	/* replace config (always spends data) */
	ret = sr_replace_config(sr_session, YM_COMMON, data, 0, 0);
	if (ret) {
		printf("failed to replace configuration, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

	ret = sr_session_stop(sr_session);
	if (ret) {
		printf("failed to stop sysrepo session, %s\n", sr_strerror(ret));
		return CLI_ECMD;
	}

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

/* Funtcions for YANG commands */

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
		if (!ret) ret = sr_session_start(sysrepo_ctx->connection, SR_DS_OPERATIONAL, &sr_session);
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

static int cmd_rpc(cmd_args_t *args)
{
	int ret = CLI_EOK;
	sr_session_ctx_t *sr_session = NULL;
	sr_val_t *output = NULL;
	size_t output_count = 0;

	//TODO: prepare input

	ret = sr_session_start(sysrepo_ctx->connection, SR_DS_RUNNING, &sr_session);
	if (!ret) ret = sr_rpc_send(sr_session, args->desc->xpath, 0, 0, args->timeout, &output, &output_count);
	if (ret) {
		printf("[] failed to send RPC operation, %s\n", sr_strerror(ret));
		sr_session_stop(sr_session);
		return CLI_ECMD;
	}

	sr_free_values(output, output_count);
	sr_session_stop(sr_session);
	return CLI_EOK;
}

static int cmd_notif(cmd_args_t *args)
{
	return CLI_EOK;
}


static void cmd_dynarray_deep_free(cmd_dynarray_t * d)
{
	dynarray_foreach(cmd, cmd_desc_t *, i, *d) {
		cmd_desc_t *cmd = *i;
		free(cmd->xpath);
		free(cmd->name);
		free(cmd);
	}
	cmd_dynarray_free(d);
}

cmd_dynarray_t dyn_cmd_table;

const cmd_desc_t cmd_table[] = {
	/* name, function, xpath, flags */
	{ CMD_EXIT,     NULL,           "", CMD_FNONE },
	{ CMD_HELP,     print_commands, "", CMD_FNONE },
	{ CMD_VERSION,  print_version,  "", CMD_FNONE },
	/* Configuration file */
	{ CMD_IMPORT,   cmd_import,     "", CMD_FNONE },
	{ CMD_EXPORT,   cmd_export,     "", CMD_FNONE },
	/* Transaction */
	{ CMD_BEGIN,    cmd_begin,      "", CMD_FINTER },
	{ CMD_COMMIT,   cmd_commmit,    "", CMD_FINTER },
	{ CMD_ABORT,    cmd_abort,      "", CMD_FINTER },
	{ CMD_VALIDATE, cmd_validate,   "", CMD_FINTER },
	{ CMD_DIFF,     cmd_diff,       "", CMD_FINTER },
	{ CMD_PERSIST,  cmd_persist,    "", CMD_FNONE },
	/*  */
	{ NULL }
};

static void cmd_help_dynarray_deep_free(cmd_help_dynarray_t * d)
{
	dynarray_foreach(cmd_help, cmd_help_t *, i, *d) {
		cmd_help_t *cmd_help = *i;
		free(cmd_help);
	}
	cmd_help_dynarray_free(d);
}

cmd_help_dynarray_t dyn_cmd_help_table;

const cmd_help_t cmd_help_table[] = {
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

static const char *create_cmd_name(const char* xpath)
{
	char* name = (char*)malloc(strlen(xpath)+1);
	if (!name){
		// memory allocation failed.
		return "";
	}
	strcpy(name,xpath);

	/* remove modules from name, the order is important */
	remove_substr(name, XPATH_BASE"/");
	remove_substr(name, XPATH_BASE);
	remove_substr(name, "/"YM_COMMON":");
	remove_substr(name, YM_COMMON":");
	remove_substr(name, YM_KRES":");
	/* replace '/' with '.' */
	replace_char(name, '/', '.');

	return name;
}

static int create_cmd(struct lys_node *node)
{
	if (node->nodetype == LYS_GROUPING ||
	    node->nodetype == LYS_USES) {
		return 0;
	}

	const char *xpath = lys_data_path(node);
	const char *name = create_cmd_name(xpath);

	if (!strlen(name)) {
		free(xpath);
		free(name);
		return 0;
	}

	cmd_desc_t *cmd = malloc(sizeof(cmd_desc_t));
	cmd->name = name;
	cmd->xpath = xpath;
	cmd->fcn = &cmd_leaf;
	cmd->flags = CMD_FNONE;

	switch (node->nodetype) {
		case LYS_CONTAINER:
			cmd->fcn = &cmd_container;
			break;
		case LYS_LEAF:
			cmd->fcn = &cmd_leaf;
			break;
		case LYS_LEAFLIST:
			cmd->fcn = &cmd_leaflist;
			break;
		case LYS_LIST:
			cmd->fcn = &cmd_list;
			break;
		case LYS_ACTION:
			cmd->fcn = &cmd_rpc;
			break;
		case LYS_RPC:
			cmd->fcn = &cmd_rpc;
			break;
		case LYS_NOTIF:
			cmd->fcn = &cmd_notif;
			break;
		default:
			cmd->fcn = &cmd_leaf;
			break;
	}

	cmd_help_t *cmd_help = malloc(sizeof(cmd_help_t));
	cmd_help->name = name;
	cmd_help->desc = node->dsc;
	cmd_help->params = "";

	cmd_help_dynarray_add(&dyn_cmd_help_table, &cmd_help);
	cmd_dynarray_add(&dyn_cmd_table, &cmd);

	return CLI_EOK;
}

static void schema_iterator(struct lys_node *root)
{
	assert(root != NULL);

	struct lys_node *node = NULL;

	LY_TREE_FOR(root, node) {
		assert(node != NULL);

		create_cmd(node);

		/* do childs only for CONTAINERS, ignore others */
		if (node->child
			&& (node->nodetype != LYS_LIST)
			&& (node->nodetype != LYS_RPC)
			&& (node->nodetype != LYS_ACTION)
			&& (node->nodetype != LYS_NOTIF)
			) {
			schema_iterator(node->child);
		}
	}
}

int create_cmd_table(sr_conn_ctx_t *sr_connection)
{
	assert(sr_connection != NULL);

	int ret = CLI_EOK;
	struct lys_node *root = NULL;
	struct ly_ctx *ly_context = NULL;
	struct lys_module *module = NULL;

	ly_context = sr_get_context(sr_connection);
	if (!ly_context) {
		printf("[] failed to get libyang context\n");
		return CLI_ERR;
	}

	/* get libyang context */
	root = ly_ctx_get_node(ly_context, NULL, XPATH_BASE, 0);
	assert(root != NULL);

	/* iterate thrue all schema nodes */
	schema_iterator(root);

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

	return 0;
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
		cmd_help_t *cmd_help = *i;
		printf(" %-40s %-10s %s\n", cmd_help->name, cmd_help->params, cmd_help->desc);
	}

	printf("\n"
		   "Note:\n"
		   "");

	return 0;
}
