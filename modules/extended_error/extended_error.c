#include "lib/module.h"
#include "daemon/engine.h"

/* TODO move to libknot, in src/libknot/rrtype/opt.h */
#define KNOT_EDNS_OPTION_EXTENDED_ERROR 65500

static int extended_error_finalize(kr_layer_t *ctx) {
	struct kr_request *req = ctx->req;
	const knot_rrset_t *src_opt = req->qsource.packet->opt_rr;
	const struct extended_error_t *ee = &req->extended_error;
	
	if (!req->extended_error.valid || src_opt == NULL) {
		return ctx->state;
	}

	/* Sanity check, answer should have EDNS as well but who knows ... */
	if (req->answer->opt_rr == NULL) {
		kr_log_verbose("[%05u.  ][exterr] no EDNS in answer, not adding Extended Error option\n", req->uid);
		assert(false);
		return ctx->state;
	}

	if (ee->response_code & ~0xFu || ee->info_code & ~0xFFFu) {
		assert(!EINVAL);
		return ctx->state;
	}
	/* Test disabled because, at this stage, Knot does not yet set
	 * the real return code (we get NOERROR even if there is a
	 * SERVFAIL)
	if (req->extended_error.response_code != knot_wire_get_rcode(req->answer->wire)) {
		kr_log_verbose("[%05u.  ][exterr] Extended error return code (%d) differs from the packet return code (%d). Strange.\n", req->uid, req->extended_error.response_code, knot_wire_get_rcode(req->answer->wire));
		return ctx->state;
	}
	*/
	
	const uint32_t header_native =
		((uint32_t)ee->retry << 31)
		| (ee->response_code << 12)
		| ee->info_code;
	const size_t extra_len = ee->extra_text ? strlen(ee->extra_text) : 0;
	uint8_t buf[sizeof(header_native) + extra_len];
	knot_wire_write_u32(buf, header_native);
	if (extra_len) {
		memcpy(buf + sizeof(header_native), ee->extra_text, extra_len);
	}

	if (knot_edns_add_option(req->answer->opt_rr, KNOT_EDNS_OPTION_EXTENDED_ERROR,
				 sizeof(buf), buf, &req->pool) != KNOT_EOK) {
		/* something went wrong and there is no way to salvage content of OPT RRset */
		kr_log_verbose("[%05u.  ][exterr] unable to add Extended Error option\n", req->uid);
		knot_rrset_clear(req->answer->opt_rr, &req->pool);
	}
	return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *extended_error_layer(struct kr_module *module)
{
	static const kr_layer_api_t _layer = {
		.answer_finalize = &extended_error_finalize,
	};
	return &_layer;
}

KR_EXPORT
int extended_error_init(struct kr_module *module) {
	return kr_ok();
}

KR_MODULE_EXPORT(extended_error)
