#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/sysinfo.h>
#include <uv.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "modules/sysrepo/common/sysrepo_utils.h"
#include "modules/sysrepo/common/string_helper.h"
#include "sysrepo_client.h"
#include "sdbus_client.h"
#include "lib/utils.h"
#include "watcher.h"

#define XPATH_SERVER		XPATH_BASE"/server"

/* Configuration data callbacks */

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

		err = sr_get_changes_iter(session, XPATH_SERVER"/*/.", &it);
		if (err != SR_ERR_OK) goto cleanup;

		while ((sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {

			const char *leaf = remove_substr(new_value->xpath, XPATH_SERVER"/cznic-resolver-knot:");

			if (!strcmp(leaf, "start-on-boot"))
				server_conf.start_on_boot = new_value->data.bool_val;
			else if (!strcmp(leaf, "kresd-instances"))
				server_conf.kresd_inst = new_value->data.uint8_val;
			else if (!strcmp(leaf, "use-cache-gc"))
				server_conf.start_cache_gc = new_value->data.bool_val;
			else if (!strcmp(leaf, "persistent-configuration"))
				server_conf.persist_conf = new_value->data.bool_val;

			sr_free_val(old_value);
			sr_free_val(new_value);
		}

		if (server_conf.start_on_boot)
		{
			control_knot_resolver(UNIT_START);
		}

		cleanup:
		sr_free_change_iter(it);

		if(err != SR_ERR_OK && err != SR_ERR_NOT_FOUND)
			printf("Error: %s\n",sr_strerror(err));
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
		printf("tls sticket secret\n");
	}
	else if(event == SR_EV_ABORT)
	{
		/* abortion actions */
	}

	return SR_ERR_OK;
}



/* RPC operations callbacks*/

static int rpc_resolver_start_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	control_knot_resolver(UNIT_START);

	return 0;
}

static int rpc_resolver_stop_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	control_knot_resolver(UNIT_STOP);

	return 0;
}

static int rpc_resolver_restart_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	control_knot_resolver(UNIT_RESTART);

	return 0;
}

static int rpc_cache_gc_start_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{

	control_cache_gc(UNIT_START);

	return 0;
}

static int rpc_cache_gc_stop_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	control_cache_gc(UNIT_STOP);
	return 0;
}

static int rpc_cache_gc_restart_cb(sr_session_ctx_t *session, const char *path,
const sr_val_t *input, const size_t input_cnt, sr_event_t event,
uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	control_cache_gc(UNIT_RESTART);
	return 0;
}

static int sysrepo_subscr_register(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription)
{
	int err = SR_ERR_OK;

	/* Configuration changes subscriptions */

	err = sr_module_change_subscribe(session, YM_COMMON, XPATH_SERVER,
	server_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_ENABLED, subscription);
	if (err != SR_ERR_OK) return err;

	err = sr_module_change_subscribe(session, YM_COMMON, XPATH_TLS_SECRET,
	tls_sticket_secret_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != SR_ERR_OK) return err;

	/* DNS resolver RPCs subscriptions */

	err = sr_rpc_subscribe(session, XPATH_RPC_BASE":start", rpc_resolver_start_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_RPC_BASE":stop", rpc_resolver_stop_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_RPC_BASE":restart", rpc_resolver_restart_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	/* Garbage Collector RPCs subscriptions */

	err = sr_rpc_subscribe(session, XPATH_GC"/start", rpc_cache_gc_start_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_GC"/stop", rpc_cache_gc_stop_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	err = sr_rpc_subscribe(session, XPATH_GC"/restart", rpc_cache_gc_restart_cb, NULL, 0,
	SR_SUBSCR_NO_THREAD|SR_SUBSCR_CTX_REUSE, subscription);
	if (err != 0) return err;

	return err;
}

/*----------------------------------------------------------------------------*/

static void el_subscr_finish_closing(uv_handle_t *handle)
{
	sysrepo_uv_ctx_t *el_subscr = handle->data;
	assert(el_subscr);
	free(el_subscr);
}

/** Free a event loop subscription. */
static void el_subscription_free(sysrepo_uv_ctx_t *el_subscr)
{
	sr_disconnect(el_subscr->connection);
	uv_close((uv_handle_t *)&el_subscr->uv_handle, el_subscr_finish_closing);
}

static void el_subscr_cb_tramp(uv_poll_t *handle, int status, int events)
{
	sysrepo_uv_ctx_t *el_subscr = handle->data;
	el_subscr->callback(el_subscr, status);
}

static void el_subscr_cb(sysrepo_uv_ctx_t *el_subscr, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
	sr_process_events(el_subscr->subscription, el_subscr->session,NULL);
}

int sysrepo_client_init(uv_loop_t *loop)
{
	int ret = SR_ERR_OK;
	sr_conn_ctx_t *sr_connection = NULL;
	sr_session_ctx_t *sr_session = NULL;
	sr_subscription_ctx_t *sr_subscription = NULL;

	if (!ret) ret = sr_connect(0, &sr_connection);
	if (!ret) ret = sr_connection_recover(sr_connection);
	if (!ret) ret = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
	if (!ret) ret = sysrepo_subscr_register(sr_session, &sr_subscription);
	if (ret){
		kr_log_error(
			"[sysrepo] failed to initialize sysrepo subscriptions:  %s\n",
			sr_strerror(ret));
		return ret;
	}

	struct sysrepo_uv_ctx *sr_ctx = malloc(sizeof(*sr_ctx));
	sr_ctx->connection = sr_connection;
	sr_ctx->session = sr_session;
	sr_ctx->callback = el_subscr_cb;
	sr_ctx->subscription = sr_subscription;

	int pipe;
	ret = sr_get_event_pipe(sr_subscription, &pipe);
	if (ret != SR_ERR_OK) {
		kr_log_error("[sysrepo] failed to get sysrepo event pipe:  %s\n", sr_strerror(ret));
		free(sr_ctx);
		return ret;
	}
	ret = uv_poll_init(loop, &sr_ctx->uv_handle, pipe);
	if (ret) {
		kr_log_error("[libuv] failed to initialize uv_poll:  %s\n", uv_strerror(ret));
		free(sr_ctx);
		return ret;
	}
	sr_ctx->uv_handle.data = sr_ctx;
	ret = uv_poll_start(&sr_ctx->uv_handle, UV_READABLE, el_subscr_cb_tramp);
	if (ret) {
		kr_log_error("[libuv] failed to start uv_poll:  %s\n", uv_strerror(ret));
		el_subscription_free(sr_ctx);
		return ret;
	}

	the_watcher->sysrepo = sr_ctx;

	return ret;
}

int sysrepo_client_deinit(uv_loop_t *loop)
{
	struct  sysrepo_uv_ctx *sysrepo_ctx = the_watcher->sysrepo;
	el_subscription_free(sysrepo_ctx);

	return 0;
}