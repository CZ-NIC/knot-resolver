#pragma once

#define SPACE			"  "
#define PROGRAM_NAME	"kresc"

typedef struct cmd_help cmd_help_t;

/*
typedef struct cmd_desc cmd_desc_t;

typedef struct {
	const cmd_desc_t *desc;
	knot_ctl_t *ctl;
	int argc;
	const char **argv;
	char flags[4];
	bool force;
	bool blocking;
} cmd_args_t;

struct cmd_desc {
	const char *name;
	int (*fcn)(cmd_args_t *);
	ctl_cmd_t cmd;
	cmd_flag_t flags;
};
*/
struct cmd_help{
	const char *name;
	const char *params;
	const char *desc;
};

void print_version();

void print_commands_help();
