#pragma once

#include <sysrepo.h>
#include <uv.h>

#include "modules/sysrepo/common/sysrepo_utils.h"

typedef struct sysrepo_uv_ctx sysrepo_uv_ctx_t;
/** Callback for our sysrepo subscriptions */
typedef void (*sysrepo_uv_cb)(sysrepo_uv_ctx_t *sysrepo_ctx, int status);

/** Context for our sysrepo subscriptions.
 * might add some other fields in future */
struct sysrepo_uv_ctx {
	sr_conn_ctx_t *connection;
	sr_session_ctx_t * session;
	sr_subscription_ctx_t *subscription;
	sysrepo_uv_cb callback;
	uv_poll_t uv_handle;
};

int set_tst_secret(const char *new_secret);

sysrepo_uv_ctx_t *sysrepo_client_init(uv_loop_t *loop);

int sysrepo_client_deinit(sysrepo_uv_ctx_t *sysrepo_ctx);
