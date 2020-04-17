#pragma once

#include <stdbool.h>


struct cmd_desc;
typedef struct cmd_desc cmd_desc_t;

typedef struct {
    const cmd_desc_t *desc;
    int argc;
    const char **argv;
} cmd_args_t;

struct cmd_desc {
    const char *name;
    void (*fcn)(void);
    const char *xpath;
};

typedef struct {
    const char *name;
    const char *params;
    const char *desc;
} cmd_help_t;

extern const cmd_desc_t cmd_table[];

void print_commands(void);
