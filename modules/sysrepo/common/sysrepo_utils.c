/*
	inspired by sysrepocfg utility
	https://github.com/sysrepo/sysrepo/blob/devel/src/executables/sysrepocfg.c
*/

#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "lib/utils.h"
#include "sysrepo_utils.h"
#include "string_helper.h"


static void ly_error_print(struct ly_ctx *ctx)
{
	struct ly_err_item *e;

	for (e = ly_err_first(ctx); e; e = e->next) {
		kr_log_error("[libyang] %s\n", e->msg);
	}

	ly_err_clean(ctx, NULL);
}

static const char *strdatastore(sr_datastore_t ds)
{
	const char *str_ds;

	switch ((int)ds)
	{
	case SR_DS_RUNNING:
		str_ds = "running";
		break;
	case SR_DS_STARTUP:
		str_ds = "startup";
		break;
	case SR_DS_CANDIDATE:
		str_ds = "candidate";
		break;
	case SR_DS_OPERATIONAL:
		str_ds = "operational";
		break;
	default:
		str_ds = "unknown";
		break;
	}

	return str_ds;
}

int sysrepo_repository_configure(sr_conn_ctx_t *connection, const char *mods_dir)
{
	int ret = 0;
	char *common_path, *kres_path;
	const char *features[1] = {"set-group"};

	/* setup paths to modules */
	common_path = concat(mods_dir, "/"YM_COMMON".yang");
	kres_path = concat(mods_dir, "/"YM_KRES".yang");

	/* Install/Update common module*/
	ret = sr_install_module(connection, common_path, mods_dir, features , 1);
	if (ret == 6){
		kr_log_info(
			"[sysrepo] module '%s' exists, trying to update\n", YM_COMMON);
		ret = sr_update_module(connection,  common_path, mods_dir);
	}
	if (ret){
		kr_log_error(
			"[sysrepo] failed to install/update '%s' module, %s\n",
			YM_COMMON, sr_strerror(ret));
	}

	/* Install/Update kres module*/
	ret = sr_install_module(connection, kres_path, mods_dir, NULL, 0);
	if (ret == 6){
		ret = sr_update_module(connection,  kres_path, mods_dir);
		kr_log_info(
			"[sysrepo] module '%s' exists, trying to update\n", YM_KRES);
	}
	if (ret){
		kr_log_error(
			"[sysrepo] failed to install/update '%s' module, %s\n",
			YM_KRES, sr_strerror(ret));
	}

	free(common_path);
	free(kres_path);
	return ret;
}

static int load_config_file(sr_session_ctx_t *sess, const char *file_path,
LYD_FORMAT format, int flags, struct lyd_node **data)
{
	char *ptr;
	struct ly_ctx *ly_ctx;

	ly_ctx = (struct ly_ctx *)sr_get_context(sr_session_get_connection(sess));

	if (!file_path){
		kr_log_error(
			"[sysrepo] missing file path\n");
		return 1;
	}

	if (format == LYD_UNKNOWN) {
		if (!file_path) {
			kr_log_error("[sysrepo] missing file path\n");
			return 1;
		}

		ptr = strrchr(file_path, '.');
		if (ptr && !strcmp(ptr, ".xml")) {
			format = LYD_XML;
		} else if (ptr && !strcmp(ptr, ".json")) {
			format = LYD_JSON;
		} else if (ptr && !strcmp(ptr, ".lyb")) {
			format = LYD_LYB;
		} else {
			kr_log_error(
				"[sysrepo] failed to detect format of '%s'\n", file_path);
			return 1;
		}
	}

	/* do not validate candidate data */
	if (sr_session_get_ds(sess) == SR_DS_CANDIDATE) {
		flags |= LYD_OPT_TRUSTED;
	}

	*data = lyd_parse_path(ly_ctx, file_path, format, flags, NULL);
	if (ly_errno) {
		ly_error_print(ly_ctx);
		kr_log_error("[sysrepo] failed to parse data\n");
		return 1;
	}
	return 0;
}

int import_from_file(sr_session_ctx_t *session, const char *file_path,
const char *module_name, LYD_FORMAT format, int not_strict, int timeout_s)
{
	int ret = 0;
	struct lyd_node *data;
	int flags = LYD_OPT_CONFIG | (not_strict ? 0 : LYD_OPT_STRICT);

	ret = load_config_file(session, file_path, format, flags, &data);
	if (ret) {
		kr_log_error("[sysrepo] failed to load configuration file\n");
		return 1;
	}

	ret = sr_replace_config(session, module_name,
		data, sr_session_get_ds(session), timeout_s * 1000);

	if (ret) {
		kr_log_error(
			"[sysrepo] failed to replace %s  configuration: %s\n",
			strdatastore(sr_session_get_ds(session)), sr_strerror(ret));
		return 1;
	}
	return 0;
}

int export_to_file(sr_session_ctx_t *sess, const char *file_path,
const char *xpath, LYD_FORMAT format, uint32_t max_depth, int timeout_s)
{
	int ret = SR_ERR_OK;
	FILE *file = NULL;
	struct lyd_node *data;

	if (format == LYD_UNKNOWN) {
		format = LYD_JSON;
	}

	file = fopen(file_path, "w");
	if (!file) {
		kr_log_error("[sysrepo] failed to open '%s' for writing, %s\n", file_path, strerror(errno));
		goto cleanup;
	}

	ret = sr_get_data(sess, xpath, max_depth, timeout_s * 1000, 0, &data);
	if (ret != SR_ERR_OK) {
		kr_log_error("[sysrepo] failed to get data, %s\n", sr_strerror(ret));
		if (file) {
			fclose(file);
		}
		goto cleanup;
	}

	/* print exported data */
	lyd_print_file(file, data, format, LYP_FORMAT | LYP_WITHSIBLINGS);
	lyd_free_withsiblings(data);

	cleanup:
	if (file) {
		fclose(file);
	}
	return ret;
}