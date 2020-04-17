#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "common.h"

/* Static commands */
#define CMD_EXIT        "exit"
#define CMD_HELP        "help"
#define CMD_VERSION	    "version"

#define CMD_BEGIN       "begin"
#define CMD_COMMIT      "commit"
#define CMD_ABORT       "abort"
#define CMD_VALIDATE    "validate"
#define CMD_DIFF        "diff"


const cmd_desc_t cmd_table[] = {
    /* name, function, xpath */
    { CMD_EXIT,     NULL,           "" },
    { CMD_HELP,     print_commands, "" },
    { CMD_VERSION,  print_version,  "" },
    { NULL }
};

static const cmd_help_t cmd_help_table[] = {
    /* name, arguments, description */
    { CMD_EXIT,    "", "Exit the program" },
    { CMD_HELP,    "", "Print the program help" },
    { CMD_VERSION, "", "Print the program version" },
    { NULL }
};

void print_commands(void)
{
    printf("\nCommands:\n");

    for (const cmd_help_t *cmd = cmd_help_table; cmd->name != NULL; cmd++) {
        printf(" %-18s %-38s %s\n", cmd->name, cmd->params, cmd->desc);
    }

    printf("\n"
       "Note:\n"
       "");
}