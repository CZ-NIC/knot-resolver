#include <uv.h>
#include <sysrepo.h>

#include "lib/utils.h"
#include "sysrepo_ctx.h"


static void sysrepo_subscr_finish_closing(uv_handle_t *handle)
{
	sysrepo_ctx_t *sysrepo = handle->data;
	assert(sysrepo);
	free(sysrepo);
}

/** Free a event loop subscription. */
static void sysrepo_subscription_free(sysrepo_ctx_t *sysrepo)
{
	sr_disconnect(sysrepo->connection);
	uv_close((uv_handle_t *)&sysrepo->uv_handle, sysrepo_subscr_finish_closing);
}

static void sysrepo_subscr_cb_tramp(uv_poll_t *handle, int status, int events)
{
	sysrepo_ctx_t *sysrepo = handle->data;
	sysrepo->callback(sysrepo, status);
}

static void sysrepo_subscr_cb(sysrepo_ctx_t *sysrepo, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
	sr_process_events(sysrepo->subscription, sysrepo->session,NULL);
}

sysrepo_ctx_t *sysrepo_ctx_init()
{
	sr_conn_ctx_t *sr_connection = NULL;
	sr_session_ctx_t *sr_session = NULL;
	sr_subscription_ctx_t *sr_subscription = NULL;

	int ret = sr_connect(0, &sr_connection);
	if (!ret) ret = sr_session_start(sr_connection, SR_DS_RUNNING, &sr_session);
	if (ret){
		kr_log_error(
			"[sysrepo] failed to start sysrepo session:  %s\n",
			sr_strerror(ret));
		return NULL;
	}

	sysrepo_ctx_t *sysrepo = malloc(sizeof(sysrepo_ctx_t));
	sysrepo->connection = sr_connection;
	sysrepo->session = sr_session;
	sysrepo->callback = sysrepo_subscr_cb;
	sysrepo->subscription = sr_subscription;

	return sysrepo;
}

int sysrepo_ctx_start(uv_loop_t *loop, sysrepo_ctx_t *sysrepo)
{
	int pipe;
	int ret = sr_get_event_pipe(sysrepo->subscription, &pipe);
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

int sysrepo_ctx_deinit(sysrepo_ctx_t *sysrepo)
{
	sysrepo_subscription_free(sysrepo);

	return 0;
}