#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <sysrepo.h>


typedef struct conv_struct conv_struct_t;

struct conv_struct {
    char *xpath;
};

int conf_cache(sr_val_t *value);
