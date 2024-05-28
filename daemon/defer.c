#include "daemon/defer.h"
#include "lib/kru.h"

// TODO: move kru_defer to another file

#include "daemon/session2.h"

defer_sample_state_t defer_sample_state = {
	.do_sample = true, // FIXME: start with false, set to true based on config when opening KRU
	.is_accounting = 0,
};


static enum protolayer_iter_cb_result pl_defer_unwrap(
		void *sess_data, void *iter_data,
		struct protolayer_iter_ctx *ctx)
{

	kr_log_notice(DEVEL, "DEFER: %s\n",
			kr_straddr(&defer_sample_state.addr.ip));

	return protolayer_continue(ctx);
	//return protolayer_async();
}

void defer_init(void) {
	protolayer_globals[PROTOLAYER_TYPE_DEFER].unwrap = pl_defer_unwrap;
}
