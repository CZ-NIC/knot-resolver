/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file dga_filter.c
 * @brief blocks DGA domains using ML
 *
 */

#include <onnxruntime_c_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpsl.h>
#include "lib/layer.h"
#include "lib/resolve.h"

#define DGA_INPUT_DIMS 2
#define DGA_OUTPUT_PROB_TENSOR_POS 1
#define DGA_OUTPUT_PROB_DATA_POS 1

#define DGA_FAIL_PROB 0.0f

#define ORT_CHECK(expr, label)  \
	do {                        \
		status = (expr);        \
		if (status) goto label; \
	} while (0)

struct dgad_context{
	OrtEnv*       env;
	OrtSession*   session;
	OrtAllocator* allocator;
	char*         input_name;
	char**        output_names;
	size_t        num_inputs;
	size_t        num_outputs;
};

void model_context_deinit(struct dgad_context* ctx)
{
	OrtStatus* status = NULL;
	const OrtApi* api;

	if (!ctx) return;

	api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	if (ctx->input_name) {
		status = api->AllocatorFree(ctx->allocator, ctx->input_name);
		if (status) {
			api->ReleaseStatus(status);
			status = NULL;
		}
		ctx->input_name = NULL;
	}

	if (ctx->output_names) {
		for (size_t i = 0; i < ctx->num_outputs; i++) {
			if (ctx->output_names[i]) {
				status = api->AllocatorFree(ctx->allocator, ctx->output_names[i]);
				if (status) {
					api->ReleaseStatus(status);
					status = NULL;
				}
			}
		}
		free(ctx->output_names);
		ctx->output_names = NULL;
	}

	if (ctx->session) {
		api->ReleaseSession(ctx->session);
		ctx->session = NULL;
	}

	if (ctx->env) {
		api->ReleaseEnv(ctx->env);
		ctx->env = NULL;
	}
}

int model_context_init(struct dgad_context* ctx, const char* model_path)
{
	OrtSessionOptions* session_options;
	OrtStatus* status = NULL;

	const OrtApi* api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	ORT_CHECK(api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "dga-classification", &ctx->env),
			fail);
	ORT_CHECK(api->CreateSessionOptions(&session_options),
			fail);
	ORT_CHECK(api->CreateSession(ctx->env, model_path, session_options, &ctx->session),
			fail);

	api->ReleaseSessionOptions(session_options);

	ORT_CHECK(api->GetAllocatorWithDefaultOptions(&(ctx->allocator)),
			fail);

	ORT_CHECK(api->SessionGetInputName(ctx->session, 0, ctx->allocator, &(ctx->input_name)),
			fail);
	ORT_CHECK(api->SessionGetInputCount(ctx->session, &(ctx->num_inputs)),
			fail);
	ORT_CHECK(api->SessionGetOutputCount(ctx->session, &(ctx->num_outputs)),
			fail);

	ctx->output_names = (char**)calloc(ctx->num_outputs, sizeof(char*));
	if (!ctx->output_names) goto fail;

	for (size_t i = 0; i < ctx->num_outputs; i++) {
		ORT_CHECK(api->SessionGetOutputName(ctx->session, i, ctx->allocator,
				&(ctx->output_names[i])),
				fail);
	}

	return kr_ok();

fail:
	model_context_deinit(ctx);
	if (status) {
		fprintf(stderr, "create_context failed: %s\n", api->GetErrorMessage(status));
		api->ReleaseStatus(status);
	}
	return kr_error(ENOMEM);
}

float get_model_inference(struct dgad_context* ctx, const char* name)
{
	const OrtApi* api;
	OrtStatus* status = NULL;
	int64_t dims[DGA_INPUT_DIMS] = {1, 1};

	const char* input_names[] = { ctx->input_name };
	OrtValue* input_tensor = NULL;
	OrtValue* input_tensors[ctx->num_inputs];
	OrtValue* output_tensors[ctx->num_outputs];

	float prob_dga = DGA_FAIL_PROB;

	if (!ctx) return DGA_FAIL_PROB;

	api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	ORT_CHECK(api->CreateTensorAsOrtValue(ctx->allocator, dims, DGA_INPUT_DIMS,
			ONNX_TENSOR_ELEMENT_DATA_TYPE_STRING, &input_tensor),
			fail);
	ORT_CHECK(api->FillStringTensor(input_tensor, &name, ctx->num_inputs),
			input_release_fail);

	input_tensors[0] = input_tensor;
	memset(output_tensors, 0, sizeof(output_tensors));

	ORT_CHECK(api->Run(ctx->session, NULL, 
			input_names, (const OrtValue* const*)input_tensors, ctx->num_inputs,
			(const char* const*)ctx->output_names, ctx->num_outputs, output_tensors),
			input_release_fail);

	if (output_tensors[DGA_OUTPUT_PROB_TENSOR_POS]) {
		float* data;
		ORT_CHECK(api->GetTensorMutableData(output_tensors[1], (void**)&data),
				output_release_fail);
		if (data[DGA_OUTPUT_PROB_DATA_POS]) prob_dga = 1 - data[DGA_OUTPUT_PROB_DATA_POS];
	}

output_release_fail:
	for (int i = 0; i < ctx->num_outputs; i++) api->ReleaseValue(output_tensors[i]);
input_release_fail:
	api->ReleaseValue(input_tensor);
fail:
	if (status) api->ReleaseStatus(status);
	return prob_dga;
}

char *get_label_before_suffix(knot_dname_t *domain)
{
	char str_domain[256];
	const psl_ctx_t *psl;
	const char *regdom;
	size_t domain_len;
	char *copy;
	char *dot;

	if (!domain) return NULL;

	knot_dname_to_str(str_domain, domain, sizeof(str_domain));

	psl = psl_builtin();
	if (!psl) return NULL;

	regdom = psl_registrable_domain(psl, (char *)str_domain);
	if (!regdom) return NULL;

	domain_len = strnlen(regdom, 256);
	copy = malloc(domain_len + 1);
	if (!copy) return NULL;

	memcpy(copy, regdom, domain_len);
	copy[domain_len] = '\0';

	dot = strchr(copy, '.');
	if (dot) *dot = '\0';

	return copy;
}

static int refuse_dga_query(kr_layer_t *ctx)
{
	knot_pkt_t *answer;
	struct kr_request *req = ctx->req;
	uint8_t rd = knot_wire_get_rd(req->qsource.packet->wire);
	if (rd)
		return ctx->state;

	answer = kr_request_ensure_answer(req);
	if (!answer)
		return ctx->state;
	knot_wire_set_rcode(answer->wire, KNOT_RCODE_NXDOMAIN);
	knot_wire_clear_ad(answer->wire);
	kr_request_set_extended_error(req, KNOT_EDNS_EDE_BLOCKED, "7L5X");
	ctx->state = KR_STATE_DONE;
	return ctx->state;
}

static int check_for_dga(kr_layer_t *ctx)
{
	float dga_prob;
	struct kr_module *module = ctx->api->data;
	struct dgad_context* dgad_ctx = module->data;
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	if (!qry || !qry->sname || qry->flags.CACHED)
		return ctx->state;

	char *label = get_label_before_suffix(qry->sname);
	if (label){
		dga_prob = get_model_inference(dgad_ctx, label);
		printf("Second Level Domain: %s, DGA probability: %f\n", label, dga_prob); // Temporary
		free(label);
		if (dga_prob > 0.5) return refuse_dga_query(ctx);
	}

	return ctx->state;
}

KR_EXPORT
int dga_filter_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.begin = &check_for_dga,
	};

	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
		{ NULL, NULL, NULL }
	};
	module->props = props;

	struct dgad_context *data = calloc(1, sizeof(struct dgad_context));
	if (!data)
		return kr_error(ENOMEM);

	int ret = model_context_init(data, "dga_detector.onnx");
	if (ret) {
		free(data);
		return kr_error(ret);
	}

	module->data = data;
	return kr_ok();
}

KR_EXPORT
int dga_filter_deinit(struct kr_module *module)
{
	struct dgad_context *data = module->data;
	if (data) {
		model_context_deinit(data);
		free(data);
		module->data = NULL;
	}
	return kr_ok();
}

KR_MODULE_EXPORT(dga_filter)
