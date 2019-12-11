
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#include "kresconfig.h"
#include "commands.h"
#include "utils/common/string_helper.h"
#include "utils/common/sysrepo_conf.h"

/* kresc static commands */
#define CMD_EXIT        "exit"
#define CMD_HELP        "help"
#define CMD_VERSION     "version"


static const cmd_help_t static_cmd_table[] = {
    { CMD_EXIT,         "",                         "Exit interactive mode." },
    { CMD_HELP,         "",                         "Show help." },
    { CMD_VERSION,      "",                         "Show version" },
	{ NULL }
};

void print_version()
{
	printf("%s (Knot Resolver), version %s\n", PROGRAM_NAME, PACKAGE_VERSION);
}

void print_examples()
{
    printf("\nExamples:\n");

    // TODO: add some configuration examples
    printf("");
}

void print_commands_help()
{
	for (const cmd_help_t *cmd = static_cmd_table; cmd->name != NULL; cmd++)
    {
		printf(SPACE"%-12s %-12s %s\n", cmd->name, cmd->params, cmd->desc);
	}
}

int generate_ym_cmd_table()
{
    int sr_rc = SR_ERR_OK;
    struct lyd_node *subtree = NULL;
    sr_conn_ctx_t *sr_connection = NULL;
    sr_session_ctx_t *sr_session = NULL;

    sr_rc = sr_connect(0, &sr_connection);
    if (sr_rc != SR_ERR_OK) goto cleanup;

    sr_rc = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
    if (sr_rc != SR_ERR_OK) goto cleanup;

    // TODO: code to convert yang model schema to commands table

    cleanup:
    if (sr_rc != SR_ERR_OK) printf("Error (%s)\n", sr_strerror(sr_rc));
    sr_disconnect(sr_connection);
    lyd_free_withsiblings(subtree);

    return SR_ERR_OK;
}
