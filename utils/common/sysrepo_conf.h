# pragma once

#include <string.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#define YM_DIR        	""
#define YM_COMMON       "cznic-resolver-common"
#define YM_KNOT         "cznic-resolver-knot"
#define XPATH_BASE      "/" YM_COMMON ":dns-resolver"

/** This function will configure sysrepo for usage wit Knot Resolver */
int configure_sysrepo(sr_conn_ctx_t *connection);

/** This function will instal startup datastore for common resolver data model */
//int install_startup_configuration(char *file_path, LYD_FORMAT file_format, kres_uv_subscr_t *client_ctx);
