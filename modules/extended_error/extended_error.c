#include <libknot/rrtype/opt.h>

#include "lib/module.h"
#include "daemon/engine.h"

static int extended_error_finalize(kr_layer_t *ctx) {
	struct kr_request *req = ctx->req;
	const knot_rrset_t *src_opt = req->qsource.packet->opt_rr;
	const struct kr_extended_error *ede = &req->extended_error;

	if (ede->info_code == KNOT_EDNS_EDE_NONE  /* no extended error */
	    || src_opt == NULL  /* no EDNS in query */
	    || kr_fails_assert(ede->info_code >= 0 && ede->info_code < UINT16_MAX)  /* info code out of range */
	    || kr_fails_assert(req->answer->opt_rr)  /* sanity check - answer should have EDNS */
	    ) {
		return ctx->state;
	}

	const uint16_t info_code = (uint16_t)ede->info_code;
	const size_t extra_len = ede->extra_text ? strlen(ede->extra_text) : 0;
	uint8_t buf[sizeof(info_code) + extra_len];
	knot_wire_write_u16(buf, info_code);
	if (extra_len)
		memcpy(buf + sizeof(info_code), ede->extra_text, extra_len);

	if (knot_edns_add_option(req->answer->opt_rr, KNOT_EDNS_OPTION_EDE,
				 sizeof(buf), buf, &req->pool) != KNOT_EOK) {
		/* something went wrong and there is no way to salvage content of OPT RRset */
		kr_log_req(req, 0, 0, EDE, "unable to add Extended Error option\n");
		knot_rrset_clear(req->answer->opt_rr, &req->pool);
	}

	return ctx->state;
}

KR_EXPORT
int extended_error_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.answer_finalize = &extended_error_finalize,
	};
	layer.data = module;
	module->layer = &layer;

	return kr_ok();
}

KR_MODULE_EXPORT(extended_error)
