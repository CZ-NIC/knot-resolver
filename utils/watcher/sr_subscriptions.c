#include <lua.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include "kresconfig.h"

#include "sr_subscriptions.h"
#include "dbus_control.h"
#include "watcher.h"
#include "worker.h"

#include "modules/sysrepo/common/sysrepo.h"
#include "modules/sysrepo/common/string_helper.h"

#define XPATH_SERVER        XPATH_BASE"/server"
#define XPATH_INSTANCES     XPATH_BASE"/"YM_KRES":instances"
#define XPATH_TST_SECRET    XPATH_BASE"/network/tls/"YM_KRES":sticket-secret"
#define XPATH_CACHE_PREFILL XPATH_BASE"/cache/"YM_KRES":prefill"
#define XPATH_STATUS        XPATH_SERVER"/"YM_KRES":status"
#define XPATH_VERSION       XPATH_SERVER"/package-version"


static int kresd_instances_start(const char *method)
{
	char xpath[128];
	int ret = SR_ERR_OK;
	sr_val_t *vals = NULL;
	size_t i, val_count = 0;
	sysrepo_uv_ctx_t *sysrepo = the_worker->engine->watcher.sysrepo;
	int kresd_instances = the_worker->engine->watcher.config.kresd_instances;

	ret = sr_get_items(sysrepo->session, XPATH_BASE"/"YM_KRES":instances//name", 0, 0, &vals, &val_count);

	for (i = 0; i < kresd_instances; ++i) {

		char inst_name[128];
		if (i < val_count)
			sprintf(&inst_name, "%s", vals[i].data.string_val);
		else
			sprintf(&inst_name, "%ld", i);

		kresd_ctl(method,inst_name);
	}
	sr_free_values(vals, val_count);
}

static int kresd_instances_status(struct lyd_node **parent)
{
	char xpath[128];
	int ret = SR_ERR_OK;
	sr_val_t *vals = NULL;
	size_t i, val_count = 0;
	sysrepo_uv_ctx_t *sysrepo = the_worker->engine->watcher.sysrepo;
	int kresd_instances = the_worker->engine->watcher.config.kresd_instances;

	ret = sr_get_items(sysrepo->session, XPATH_BASE"/"YM_KRES":instances//name", 0, 0, &vals, &val_count);

	for (i = 0; i < kresd_instances; ++i) {

		char inst_name[128];
		char *status;

		if (i < val_count)
			sprintf(&inst_name, "%s", vals[i].data.string_val);
		else
			sprintf(&inst_name, "%ld", i);

		sprintf(&xpath, XPATH_STATUS"/kresd-instances[name='%s']", inst_name);
		kresd_get_status(inst_name, &status);
		lyd_new_path(*parent, NULL, xpath, inst_name, 0, 0);

		sprintf(&xpath, XPATH_STATUS"/kresd-instances[name='%s']/status", inst_name);
		lyd_new_path(*parent, NULL, xpath, status, 0, 0);

		free(status);
	}
	sr_free_values(vals, val_count);
}

int resolver_start()
{
	int ret = SR_ERR_OK;
	struct server_config cfg = the_worker->engine->watcher.config;

	/* If autostart => start processes */
	if (cfg.auto_start) {
		kresd_instances_start(UNIT_START);

		if (cfg.auto_cache_gc)
			cache_gc_ctl(UNIT_START);
	}

	return ret;
}

int set_tst_secret(const char *new_secret)
{
	int ret = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;

	if (!ret) ret = sr_connect(0, &connection);
	if (!ret) ret = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (!ret) ret = sr_set_item_str(session, XPATH_TST_SECRET, new_secret, NULL, 0);
	if (!ret) ret = sr_validate(session, YM_COMMON, 0);
	if (!ret) ret = sr_apply_changes(session, 0, 0);
	if (ret)
		kr_log_error(
			"[sysrepo] failed to set '%s', %s\n",
			XPATH_TST_SECRET, sr_strerror(ret));

	sr_disconnect(connection);

	return ret;
}

/* STATE DATA CALLBACKS */

static int server_status_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	/* kresd instances status */
	kresd_instances_status(parent);

	/* Cache Garbage Collector status */
	char *cache_gc_status;
	cache_gc_get_status(&cache_gc_status);
	lyd_new_path(*parent, NULL, XPATH_STATUS"/cache-gc", cache_gc_status, 0, 0);

	free(cache_gc_status);
	return SR_ERR_OK;
}

static int server_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	assert(parent!=NULL);

	char str[128];
	struct server_config cfg = the_worker->engine->watcher.config;
	lyd_new_path(*parent, NULL, XPATH_VERSION, PACKAGE_VERSION, 0, 0);

	sprintf(str, "%s", cfg.auto_start ? "true" : "false");
	lyd_new_path(*parent, NULL, XPATH_SERVER"/"YM_KRES":auto-start", str, 0, 0);

	sprintf(str, "%s", cfg.auto_cache_gc ? "true" : "false");
	lyd_new_path(*parent, NULL, XPATH_SERVER"/"YM_KRES":auto-cache-gc", str, 0, 0);

	sprintf(str, "%d", cfg.kresd_instances);
	lyd_new_path(*parent, NULL, XPATH_SERVER"/"YM_KRES":kresd-instances", str, 0, 0);

	return SR_ERR_OK;
}

static int instance_status_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	return SR_ERR_OK;
}

/* CONFIG DATA CALLBACKS */

static int server_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
sr_event_t event, uint32_t request_id, void *private_data)
{
	if(event == SR_EV_CHANGE)
	{
		/* validation actions*/
	}
	else if (event == SR_EV_DONE)
	{
		int err = SR_ERR_OK;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;
		sr_change_iter_t *it = NULL;
		struct server_config *cfg = &the_worker->engine->watcher.config;

		err = sr_get_changes_iter(session, XPATH_SERVER "/*/.", &it);
		if (err != SR_ERR_OK) goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {

			const char *leaf = remove_substr(new_value->xpath, XPATH_SERVER"/cznic-resolver-knot:");
			printf("%s\n", new_value->xpath);
			if (!strcmp(leaf, "auto-start"))
				cfg->auto_start = new_value->data.bool_val;
			else if (!strcmp(leaf, "auto-cache-gc"))
				cfg->auto_cache_gc = new_value->data.bool_val;
			else if (!strcmp(leaf, "kresd-instances"))
				cfg->kresd_instances = new_value->data.uint8_val;

			sr_free_val(old_value);
			sr_free_val(new_value);
		}

		cleanup:
		sr_free_change_iter(it);
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}

	return SR_ERR_OK;
}

static int tls_sticket_secret_change_cb(sr_session_ctx_t *session,
const char *module_name, const char *xpath, sr_event_t event,
uint32_t request_id, void *private_data)
{
	if(event == SR_EV_CHANGE)
	{
		/* validation actions*/
	}
	else if (event == SR_EV_DONE)
	{
		int ret = 0;
		uv_loop_t *loop = the_worker->loop;
		ret = tst_secret_timer_init(loop);
		if (ret){
			kr_log_error("[sysrepo] failed to init tls session ticket secret");
		}
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}

	return SR_ERR_OK;
}

static int cache_prefill_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
sr_event_t event, uint32_t request_id, void *private_data)
{
	if(event == SR_EV_CHANGE)
	{
		/* validation actions*/
	}
	else if (event == SR_EV_DONE)
	{
		int err = SR_ERR_OK;
		sr_change_oper_t oper;
		sr_val_t *old_value = NULL;
		sr_val_t *new_value = NULL;
		sr_change_iter_t *it = NULL;

		struct server_config *cfg = &the_worker->engine->watcher.config;

		err = sr_get_changes_iter(session, XPATH_CACHE_PREFILL "/*", &it);
		if (err != SR_ERR_OK) goto cleanup;

		lua_State *L = the_worker->engine->L;
		engine_cmd(L, "modules.load('prefill')",false);
		lua_getglobal(L, "prefill.config");
		lua_newtable(L);

		while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {

			printf("%s\n", new_value->xpath);
			char *leaf = strrchr(new_value->xpath, '/');

			if (leaf && !strcmp(leaf, "/origin")) {

			}
			if (leaf && !strcmp(leaf, "/url")) {
				lua_pushstring(L, new_value->data.string_val);
				lua_setfield(L, -2, "url");
			}

			if (leaf && !strcmp(leaf, "/ca-file")){
				lua_pushstring(L, new_value->data.string_val);
				lua_setfield(L, -2, "ca_file");
			}
			if (leaf && !strcmp(leaf, "/refresh-interval")) {
				lua_pushnumber(L, new_value->data.uint32_val);
				lua_setfield(L, -2, "interval");
			}

			sr_free_val(old_value);
			sr_free_val(new_value);
		}

		lua_setglobal(L, ".");
		engine_pcall(L, 1);

		cleanup:
		sr_free_change_iter(it);
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}
	return SR_ERR_OK;
}

/* RPC CALLBACKS */

/* Callback for kresd instances controll */
static int rpc_instance_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	const char *leaf = remove_substr(path, XPATH_SERVER"/");


	return 0;
}

static int rpc_resolver_start_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int ret = SR_ERR_OK;
	struct server_config cfg = the_worker->engine->watcher.config;

	kresd_instances_start(UNIT_START);

	if (cfg.auto_cache_gc)
		cache_gc_ctl(UNIT_START);

	return ret;
}

static int rpc_resolver_stop_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int ret = SR_ERR_OK;
	struct server_config cfg = the_worker->engine->watcher.config;

	kresd_instances_start(UNIT_STOP);

	cache_gc_ctl(UNIT_STOP);

	return ret;
}

static int rpc_resolver_restart_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int ret = SR_ERR_OK;
	struct server_config cfg = the_worker->engine->watcher.config;

	kresd_instances_start(UNIT_RESTART);

	if (cfg.auto_cache_gc)
		cache_gc_ctl(UNIT_RESTART);

	return ret;
}

static int rpc_cache_gc_start_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int ret = cache_gc_ctl(UNIT_START);

	return 0;
}

static int rpc_cache_gc_stop_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int ret = cache_gc_ctl(UNIT_STOP);

	return 0;
}

static int rpc_cache_gc_restart_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int ret = cache_gc_ctl(UNIT_RESTART);

	return 0;
}

int sysrepo_subscr_register(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription)
{
	int err = SR_ERR_OK;

	/* CONFIG CHANGES */

	err = sr_module_change_subscribe(session, YM_COMMON, XPATH_SERVER,
	server_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_ENABLED|SR_SUBSCR_DONE_ONLY, subscription);
	if (err != SR_ERR_OK) return err;

	err = sr_module_change_subscribe(session, YM_COMMON, XPATH_TST_SECRET,
	tls_sticket_secret_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE|SR_SUBSCR_DONE_ONLY, subscription);
	if (err != SR_ERR_OK) return err;

	err = sr_module_change_subscribe(session, YM_COMMON, XPATH_CACHE_PREFILL,
	cache_prefill_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE|SR_SUBSCR_ENABLED|SR_SUBSCR_DONE_ONLY, subscription);
	if (err != SR_ERR_OK) return err;

	/* RPC OPERATIONS */

	err = sr_rpc_subscribe(session, XPATH_RPC_BASE":start", rpc_resolver_start_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_RPC_BASE":stop", rpc_resolver_stop_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_RPC_BASE":restart", rpc_resolver_restart_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_GC"/start", rpc_cache_gc_start_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_GC"/stop", rpc_cache_gc_stop_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_GC"/restart", rpc_cache_gc_restart_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	/* STATE DATA */

	err = sr_oper_get_items_subscribe(session, YM_COMMON, XPATH_SERVER, server_cb, NULL, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != SR_ERR_OK) return err;

	err = sr_oper_get_items_subscribe(session, YM_COMMON, XPATH_STATUS, server_status_cb, NULL, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != SR_ERR_OK) return err;

	err = sr_oper_get_items_subscribe(session, YM_COMMON, XPATH_INSTANCES, instance_status_cb, NULL, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != SR_ERR_OK) return err;

	return err;
}