#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <uv.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

#include "contrib/ccan/asprintf/asprintf.h"
#include "lib/utils.h"
#include "sysrepo.h"


int valtostr(const sr_val_t *value, char **strval)
{
	if (NULL == value) {
		return 1;
	}

	switch (value->type) {
		case SR_CONTAINER_T:
		case SR_CONTAINER_PRESENCE_T:
			break;
		case SR_LIST_T:
			break;
		case SR_STRING_T:
			asprintf(strval, "%s", value->data.string_val);
			break;
		case SR_BOOL_T:
			asprintf(strval, "%s", value->data.bool_val ? "true" : "false");
			break;
		case SR_DECIMAL64_T:
			asprintf(strval, "%g", value->data.decimal64_val);
			break;
		case SR_INT8_T:
			asprintf(strval, "%"PRId8, value->data.int8_val);
			break;
		case SR_INT16_T:
			asprintf(strval, "%"PRId16, value->data.int16_val);
			break;
		case SR_INT32_T:
			asprintf(strval, "%"PRId32, value->data.int32_val);
			break;
		case SR_INT64_T:
			asprintf(strval, "%"PRId64, value->data.int64_val);
			break;
		case SR_UINT8_T:
			asprintf(strval, "%"PRIu8, value->data.uint8_val);
			break;
		case SR_UINT16_T:
			asprintf(strval, "%"PRIu16, value->data.uint16_val);
			break;
		case SR_UINT32_T:
			asprintf(strval, "%"PRIu32, value->data.uint32_val);
			break;
		case SR_UINT64_T:
			asprintf(strval, "%"PRIu64, value->data.uint64_val);
			break;
		case SR_IDENTITYREF_T:
			asprintf(strval, "%s", value->data.identityref_val);
			break;
		case SR_INSTANCEID_T:
			asprintf(strval, "%s", value->data.instanceid_val);
			break;
		case SR_BITS_T:
			asprintf(strval, "%s", value->data.bits_val);
			break;
		case SR_BINARY_T:
			asprintf(strval, "%s", value->data.binary_val);
			break;
		case SR_ENUM_T:
			asprintf(strval, "%s", value->data.enum_val);
			break;
		case SR_LEAF_EMPTY_T:
			break;
		default:
			break;
	}

	return 0;
}

static void sysrepo_subscr_finish_closing(uv_handle_t *handle)
{
	sysrepo_uv_ctx_t *sysrepo = handle->data;
	assert(sysrepo);
	free(sysrepo);
}

/** Free a event loop subscription. */
static void sysrepo_subscription_free(sysrepo_uv_ctx_t *sysrepo)
{
	sr_disconnect(sysrepo->connection);
	uv_close((uv_handle_t *)&sysrepo->uv_handle, sysrepo_subscr_finish_closing);
}

static void sysrepo_subscr_cb_tramp(uv_poll_t *handle, int status, int events)
{
	sysrepo_uv_ctx_t *sysrepo = handle->data;
	sysrepo->callback(sysrepo, status);
}

static void sysrepo_subscr_cb(sysrepo_uv_ctx_t *sysrepo, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
	sr_process_events(sysrepo->subscription, sysrepo->session,NULL);
}

sysrepo_uv_ctx_t *sysrepo_ctx_init()
{
	int ret = SR_ERR_OK;
	sr_conn_ctx_t *sr_connection = NULL;
	sr_session_ctx_t *sr_session = NULL;
	sr_subscription_ctx_t *sr_subscription = NULL;

	if (!ret) ret = sr_connect(0, &sr_connection);
	if (!ret) ret = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
	if (ret){
		kr_log_error(
			"[sysrepo] failed to start sysrepo session:  %s\n",
			sr_strerror(ret));
		return NULL;
	}

	sysrepo_uv_ctx_t *sysrepo = malloc(sizeof(sysrepo_uv_ctx_t));
	sysrepo->connection = sr_connection;
	sysrepo->session = sr_session;
	sysrepo->callback = sysrepo_subscr_cb;
	sysrepo->subscription = sr_subscription;

	return sysrepo;
}

int sysrepo_ctx_start(uv_loop_t *loop, sysrepo_uv_ctx_t *sysrepo)
{
	int ret = SR_ERR_OK;

	int pipe;
	ret = sr_get_event_pipe(sysrepo->subscription, &pipe);
	if (ret != SR_ERR_OK) {
		kr_log_error("[sysrepo] failed to get sysrepo event pipe:  %s\n", sr_strerror(ret));
		free(sysrepo);
		return ret;
	}
	ret = uv_poll_init(loop, &sysrepo->uv_handle, pipe);
	if (ret) {
		kr_log_error("[libuv] failed to initialize uv_poll:  %s\n", uv_strerror(ret));
		free(sysrepo);
		return ret;
	}
	sysrepo->uv_handle.data = sysrepo;
	ret = uv_poll_start(&sysrepo->uv_handle, UV_READABLE, sysrepo_subscr_cb_tramp);
	if (ret) {
		kr_log_error("[libuv] failed to start uv_poll:  %s\n", uv_strerror(ret));
		sysrepo_subscription_free(sysrepo);
	}
	return ret;
}

int sysrepo_ctx_deinit(sysrepo_uv_ctx_t *sysrepo)
{
	sysrepo_subscription_free(sysrepo);

	return 0;
}