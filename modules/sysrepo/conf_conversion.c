#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <sysrepo.h>
#include "conf_conversion.h"

static const conv_struct_t cache_conv_table[] = {  
	{ NULL }
};

int conf_cache(sr_val_t *value)
{
    return 0;
}