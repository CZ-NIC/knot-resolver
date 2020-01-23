#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <sysrepo.h>

#include "conversion.h"
#include "conv_funcs.h"
#include "modules/sysrepo/common/sysrepo_conf.h"


/** Configuration conversion table:
 * sysrepo config datastore <<-->> kres config */
static const conversion_row_t conversion_table[] = {
	{ NULL }
};
