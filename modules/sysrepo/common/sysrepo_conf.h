# pragma once

#include <string.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

/* sysrepo globals */
#define YM_DIR        	""
#define YM_COMMON       "cznic-resolver-common"
#define YM_KRES         "cznic-resolver-knot"
#define XPATH_BASE      "/" YM_COMMON ":dns-resolver"

/* Function to configure sysrepo repository */
int sysrepo_repo_config();