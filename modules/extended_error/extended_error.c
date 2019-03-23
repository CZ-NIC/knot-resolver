#include "lib/module.h"
#include "daemon/engine.h"

/* TODO move to libknot, in src/libknot/rrtype/opt.h */
#define KNOT_EDNS_OPTION_EXTENDED_ERROR 65500

struct extended_error_config {
	uint8_t *data;
	size_t length;
};

uint32_t serialize(struct extended_error_t err) {
	uint32_t result = 0;
	result = (u_int32_t)err.retry << 31;
	result = result + ((err.response_code & 0x0000000F) << 12);
	result = result + (err.info_code & 0x00000FFF);
	return(ntohl(result));
}
	
static int extended_error_finalize(kr_layer_t *ctx) {
	const struct kr_module *module = ctx->api->data;
	struct extended_error_config *config = module->data;
	struct kr_request *req = ctx->req;
	const knot_rrset_t *src_opt = req->qsource.packet->opt_rr;
	uint32_t data;
	
	if (!req->extended_error.valid) {
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
	
	config->length = 4 + strlen(req->extended_error.extra_text);
	config->data = mm_alloc(&req->pool, config->length);
	
        /* no EDNS in request, do nothing */
	if (src_opt == NULL)
		return ctx->state;

	/* Sanity check, answer should have EDNS as well but who knows ... */
	if (req->answer->opt_rr == NULL) {
		kr_log_verbose("[%05u.  ][exterr] no EDNS in answer, not adding Extended Error option\n", req->uid);
		knot_rrset_clear(req->answer->opt_rr, &req->pool);
		return ctx->state;
	}

	data = serialize(req->extended_error);
	memcpy(config->data, &data, config->length);
	memcpy(config->data+4, req->extended_error.extra_text, strlen(req->extended_error.extra_text));

	if (knot_edns_add_option(req->answer->opt_rr, KNOT_EDNS_OPTION_EXTENDED_ERROR,
				 config->length, config->data,
				 &req->pool) != KNOT_EOK) {
		/* something went wrong and there is no way to salvage content of OPT RRset */
		kr_log_verbose("[%05u.  ][exterr] unable to add Extended Error option\n", req->uid);
		knot_rrset_clear(req->answer->opt_rr, &req->pool);
	}
	return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *extended_error_layer(struct kr_module *module)
{
	static kr_layer_api_t _layer = {
		.answer_finalize = &extended_error_finalize,
	};
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int extended_error_init(struct kr_module *module) {
	struct extended_error_config *config = calloc(1, sizeof(struct extended_error_config));
	if (config == NULL)
		return kr_error(ENOMEM);

	module->data = config;
	return kr_ok();
}

KR_MODULE_EXPORT(extended_error)
