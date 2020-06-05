#pragma once

#include <stdbool.h>
#include <string.h>
#include <sysrepo.h>

#include "contrib/dynarray.h"
#include "process.h"


struct cmd_desc;
typedef struct cmd_desc cmd_desc_t;
typedef struct cmd_help cmd_help_t;

typedef enum {
	CMD_FNONE   = 0,
	CMD_FINTER  = 1 << 0, /* Interactive-only command. */
	CMD_FSTATE  = 2 << 0, /* State-only command */
} cmd_flag_t;

typedef struct {
	const cmd_desc_t *desc;
	const sr_datastore_t ds;
	int argc;
	const char **argv;
	int timeout;
} cmd_args_t;

struct cmd_desc {
	const char *name;
	int (*fcn)(cmd_args_t *);
	const char *xpath;
	cmd_flag_t flags;
};

struct cmd_help {
	const char *name;
	const char *params;
	const char *desc;
};

dynarray_declare(cmd, cmd_desc_t *, DYNARRAY_VISIBILITY_STATIC, 0)
    dynarray_define(cmd, cmd_desc_t *, DYNARRAY_VISIBILITY_STATIC)

dynarray_declare(cmd_help, cmd_help_t *, DYNARRAY_VISIBILITY_STATIC, 0)
    dynarray_define(cmd_help, cmd_help_t *, DYNARRAY_VISIBILITY_STATIC)

int create_cmd_table(sr_conn_ctx_t *sr_connection);

void destroy_cmd_table();

int print_version(cmd_args_t *args);

int print_commands(cmd_args_t *args);

extern cmd_dynarray_t dyn_cmd_table;
extern cmd_help_dynarray_t dyn_cmd_help_table;

extern const cmd_desc_t cmd_table[];
extern const cmd_help_t cmd_help_table[];