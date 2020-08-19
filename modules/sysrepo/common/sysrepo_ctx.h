#pragma once

#include <uv.h>
#include <sysrepo.h>

#define YM_COMMON      "cznic-resolver-common"
#define YM_KRES        "cznic-resolver-knot"
#define XPATH_BASE     "/" YM_COMMON ":dns-resolver"
#define XPATH_RPC_BASE "/"YM_COMMON
#define XPATH_GC       XPATH_BASE "/cache/" YM_KRES ":garbage-collector"


typedef struct sysrepo_ctx sysrepo_ctx_t;
/** Callback for sysrepo subscriptions */
typedef void (*sysrepo_cb)(sysrepo_ctx_t *sysrepo, int status);

/** Context for sysrepo subscriptions.
 * might add some other fields in future */
struct sysrepo_ctx {
	sr_conn_ctx_t *connection;
	sr_session_ctx_t *session;
	sr_subscription_ctx_t *subscription;
	sysrepo_cb callback;
	uv_poll_t uv_handle;
};

/** Init sysrepo context */
sysrepo_ctx_t *sysrepo_ctx_init();

/** Start subscribtion with sysrepo context */
int sysrepo_ctx_start(uv_loop_t *loop, sysrepo_ctx_t *sysrepo);

/** Destroy sysrepo context */
int sysrepo_ctx_deinit(sysrepo_ctx_t *sysrepo);


