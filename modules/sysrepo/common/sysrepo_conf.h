# pragma once

#include <string.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#define YM_COMMON           "cznic-resolver-common"
#define YM_KRES             "cznic-resolver-knot"
#define XPATH_BASE          "/" YM_COMMON ":dns-resolver"
#define XPATH_GC            XPATH_BASE"/cache/"YM_KRES":garbage-collector"
#define XPATH_RPC_BASE      "/"YM_COMMON


/** Configures sysrepo repository for usage with knot-resolver */
int sysrepo_repo_config();
