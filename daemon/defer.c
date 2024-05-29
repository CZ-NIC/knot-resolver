#include "daemon/defer.h"
#include "lib/kru.h"

#include "daemon/session2.h"

uv_check_t check_handle;

defer_sample_state_t defer_sample_state = {
	.do_sample = true, // FIXME: start with false, set to true based on config when opening KRU
	.is_accounting = 0,
};


struct protolayer_iter_ctx *defer_ctx = NULL;


static enum protolayer_iter_cb_result pl_defer_unwrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{

	if (!defer_ctx) {
		defer_ctx = ctx;
		return protolayer_async();
	}

	return protolayer_continue(ctx);
}


static void defer_queues_check(uv_check_t *handle) {
	if (defer_ctx) {
		protolayer_continue(defer_ctx);
		defer_ctx = NULL;
	}
}

void defer_init(uv_loop_t *loop) {
	protolayer_globals[PROTOLAYER_TYPE_DEFER].unwrap = pl_defer_unwrap;
	uv_check_init(loop, &check_handle);
	uv_check_start(&check_handle, defer_queues_check);
}
