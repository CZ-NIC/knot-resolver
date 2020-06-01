#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <sysrepo.h>

#include "kresconfig.h"
#include "process.h"
#include "commands.h"

/* CLI globals */
#define PROJECT_NAME    "Knot Resolver"
#define PROGRAM_NAME    "kresctl"
#define PROGRAM_DESC    "control/administration tool"
#define HISTORY_FILE    ".kresctl_history"
#define SPACE           "  "
/* default values */
#define SYSREPO_TIMEOUT 10
/* return codes */
#define CLI_EOK   0
#define CLI_ERR   1
#define CLI_ECMD  2
#define CLI_EXIT  -10


/* CLI parameters. */
typedef struct {
	int timeout;
	int max_depth;
} params_t;

/* CLI context */
typedef struct {
	sr_conn_ctx_t *connection;
	sr_session_ctx_t *session;
} sysrepo_ctx_t;

extern sysrepo_ctx_t *sysrepo_ctx;

int process_cmd(int argc, const char **argv, params_t *params);
