# pragma once

#include <sysrepo.h>
#include <libyang/libyang.h>

#define YM_COMMON			"cznic-resolver-common"
#define YM_KRES				"cznic-resolver-knot"
#define XPATH_BASE			"/" YM_COMMON ":dns-resolver"
#define XPATH_GC			XPATH_BASE"/cache/"YM_KRES":garbage-collector"
#define XPATH_RPC_BASE		"/"YM_COMMON


/** Import configuration from file, datastore is specified in session context */
int import_file_to_startup_ds(sr_session_ctx_t *sess, const char *file_path,
const char *module_name, LYD_FORMAT format, int not_strict, int timeout_s);

/** Configures sysrepo repository for usage with knot-resolver */
int sysrepo_repository_configure(sr_conn_ctx_t *connection, const char *mods_dir);
