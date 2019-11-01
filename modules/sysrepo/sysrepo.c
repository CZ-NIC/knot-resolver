#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <sysrepo.h>
#include <uv.h>

#include "lib/module.h"

typedef struct subscr subscr_t;
/** Callback for our sysrepo subscriptions */
typedef void (*subscr_cb)(subscr_t *sub, int status);

/** Context for our sysrepo subscriptions.
 * might add some other fields in future */
struct subscr {
	sr_subscription_ctx_t *sr_ctx;
	subscr_cb cb;
	uv_poll_t uv_handle;
};

void subscr_finish_closing(uv_handle_t *handle)
{
	subscr_t *sub = handle->data;
	assert(sub);
	free(sub);
}
/** Free a subscription. */
void subscr_free(subscr_t *sub)
{
	uv_close((uv_handle_t *)&sub->uv_handle, subscr_finish_closing);
}

static void subscr_cb_tramp(uv_poll_t *handle, int status, int events)
{
	subscr_t *sub = handle->data;
	sub->cb(sub, status);
}
/** Start a new subscription.  */
static subscr_t * subscr_new(sr_subscription_ctx_t *sr_sub, subscr_cb cb)
{
	int fd;
	errno = sr_get_event_pipe(sr_sub, &fd);
	if (errno != SR_ERR_OK) return NULL;
	subscr_t *sub = malloc(sizeof(*sub));
	if (!sub) return NULL;
	errno = uv_poll_init(uv_default_loop(), &sub->uv_handle, fd);
	if (errno) {
		free(sub);
		return NULL;
	}
	sub->uv_handle.data = sub;
	errno = uv_poll_start(&sub->uv_handle, UV_READABLE, subscr_cb_tramp);
	if (errno) {
		subscr_free(sub);
		return NULL;
	}
	return sub;
}



/* subscr_new(sr_sub, subscr_cb_example); */
static void subscr_cb_example(subscr_t *sub, int status)
{
	if (status) {
		/* some error */
		return;
	}
	/* normal state */
}


static void* observe(void *arg)
{
        /* ... do some observing ... */
}

int sysrepo_init(struct kr_module *module)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    const char *mod_name, *xpath = NULL;
}

int sysrepo_deinit(struct kr_module *module)
{
	/* TODO: don't forget to subscr_free() everything. */
}

KR_MODULE_EXPORT(sysrepo)
