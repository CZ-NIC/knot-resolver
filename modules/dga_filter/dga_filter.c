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
#include "dga_filter.h"

static const ModelDefinition DGA_MODEL_DEF = {
	.expected_output_probs_dims = {-1, 2}, // -1 for dynamic dimension (i. e. batch size)

	.expected_inputs = 1,
	.expected_outputs = 2,

	.output_probs_index = 1,
	.output_probs_dga_index = 0
};

struct {
	struct model_context* model;
	kr_rule_tags_t tags;
	uint16_t threshold;
} config = {0};

bool load_attempted = false;

const OrtApi* get_ort_api(void)
{
	if (!config.model)
		return OrtGetApiBase()->GetApi(ORT_API_VERSION);
	if (!config.model->api)
		config.model->api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
	return config.model->api;
}

void model_context_deinit(void)
{
	OrtStatus* status = NULL;
	const OrtApi* api;

	if (!config.model) return;

	api = get_ort_api();

	if (config.model->session_options) {
		api->ReleaseSessionOptions(config.model->session_options);
		config.model->session_options = NULL;
	}

	if (config.model->input_name) {
		status = api->AllocatorFree(config.model->allocator, config.model->input_name);
		if (status) {
			api->ReleaseStatus(status);
			status = NULL;
		}
		config.model->input_name = NULL;
	}

	if (config.model->output_names) {
		for (size_t i = 0; i < config.model->num_outputs; i++) {
			if (config.model->output_names[i]) {
				status = api->AllocatorFree(config.model->allocator, config.model->output_names[i]);
				if (status) {
					api->ReleaseStatus(status);
					status = NULL;
				}
			}
		}
		free(config.model->output_names);
		config.model->output_names = NULL;
	}

	if (config.model->session) {
		api->ReleaseSession(config.model->session);
		config.model->session = NULL;
	}

	if (config.model->env) {
		api->ReleaseEnv(config.model->env);
		config.model->env = NULL;
	}
}

static bool validate_model_definition(const char* model_path)
{
	bool valid = false;
	OrtStatus* status = NULL;
	OrtTypeInfo* type_info = NULL;
	const OrtTensorTypeAndShapeInfo* tensor_info = NULL;
	size_t dims_rank = 0;
	int64_t dims[2];

	const OrtApi* api = get_ort_api();

	if (config.model->num_inputs != DGA_MODEL_DEF.expected_inputs) {
		kr_log_crit(DGA, "failed to load ONNX model '%s': expected exactly %zu inputs, got %zu",
			model_path, DGA_MODEL_DEF.expected_inputs, config.model->num_inputs);
		goto fail;
	}

	if (config.model->num_outputs != DGA_MODEL_DEF.expected_outputs) {
		kr_log_crit(DGA, "failed to load ONNX model '%s': expected exactly %zu outputs, got %zu",
			model_path, DGA_MODEL_DEF.expected_outputs, config.model->num_outputs);
		goto fail;
	}

	// we're only interested in the output tensor with probabilities and not the label tensor
	ORT_CHECK(api->SessionGetOutputTypeInfo(config.model->session, DGA_MODEL_DEF.output_probs_index,
			&type_info),
			fail);
	ORT_CHECK(api->CastTypeInfoToTensorInfo(type_info, &tensor_info),
			fail);

	ONNXTensorElementDataType actual_type = ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;
	ORT_CHECK(api->GetTensorElementType(tensor_info, &actual_type),
			fail);
	if (actual_type != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
		kr_log_crit(DGA, "failed to load ONNX model '%s': expected float probability tensor at index %zu, got type %d",
			model_path, DGA_MODEL_DEF.output_probs_index, actual_type);
		goto fail;
	}

	ORT_CHECK(api->GetDimensionsCount(tensor_info, &dims_rank), fail);
	if (dims_rank != ARRAY_SIZE(DGA_MODEL_DEF.expected_output_probs_dims)) {
		kr_log_crit(DGA, "failed to load ONNX model '%s': expected 2D probability tensor at index %zu, got %lldD",
			model_path, DGA_MODEL_DEF.output_probs_index, (long long)dims_rank);
		goto fail;
	}
	ORT_CHECK(api->GetDimensions(tensor_info, dims, ARRAY_SIZE(dims)),
			fail);

	if (dims[0] != DGA_MODEL_DEF.expected_output_probs_dims[0] || dims[1] != DGA_MODEL_DEF.expected_output_probs_dims[1]) {
		kr_log_crit(DGA, "failed to load ONNX model '%s': expected output probability tensor shape [%lld, %lld], got [%lld, %lld]",
			model_path,
			(long long)DGA_MODEL_DEF.expected_output_probs_dims[0], (long long)DGA_MODEL_DEF.expected_output_probs_dims[1], 
			(long long)dims[0], (long long)dims[1]);
		goto fail;
	}

	valid = true;
fail:
	if (type_info) {
		api->ReleaseTypeInfo(type_info);
	}
	if (status) {
		kr_log_crit(DGA, "model validation failed: %s\n", api->GetErrorMessage(status));
		api->ReleaseStatus(status);
	}
	return valid;
}

int model_context_init(const char* model_path)
{
	OrtStatus* status = NULL;

	const OrtApi* api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	ORT_CHECK(api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "dga-classification", &config.model->env),
			fail);

	ORT_CHECK(api->CreateSessionOptions(&config.model->session_options),
			fail);
	ORT_CHECK(api->CreateSession(config.model->env, model_path, config.model->session_options, &config.model->session),
			fail);

	ORT_CHECK(api->GetAllocatorWithDefaultOptions(&(config.model->allocator)),
			fail);

	ORT_CHECK(api->SessionGetInputCount(config.model->session, &(config.model->num_inputs)),
			fail);
	ORT_CHECK(api->SessionGetOutputCount(config.model->session, &(config.model->num_outputs)),
		fail);

	if (!validate_model_definition(model_path)) {
		goto fail;
	}

	ORT_CHECK(api->SessionGetInputName(config.model->session, 0, config.model->allocator, &(config.model->input_name)),
			fail);

	config.model->output_names = (char**)calloc(config.model->num_outputs, sizeof(char*));
	if (!config.model->output_names) goto fail;

	for (size_t i = 0; i < config.model->num_outputs; i++) {
		ORT_CHECK(api->SessionGetOutputName(config.model->session, i, config.model->allocator,
				&(config.model->output_names[i])),
				fail);
	}

	return kr_ok();

fail:
	model_context_deinit();
	if (status) {
		kr_log_crit(DGA, "create_context failed: %s\n", api->GetErrorMessage(status));
		api->ReleaseStatus(status);
	}
	return kr_error(ENOMEM);
}

float get_model_inference(const char* name)
{
	const OrtApi* api;
	OrtStatus* status = NULL;
	int64_t dims[] = {1, 1}; // batch_size x 1 tensor -> [[input_string]]

	const char* input_names[] = { config.model->input_name };
	OrtValue* input_tensor = NULL;
	OrtValue* input_tensors[config.model->num_inputs];
	OrtValue* output_tensors[config.model->num_outputs];

	float prob_dga = DGA_FAIL_PROB;

	if (!config.model) return DGA_FAIL_PROB;

	api = get_ort_api();

	ORT_CHECK(api->CreateTensorAsOrtValue(config.model->allocator, dims, ARRAY_SIZE(dims),
			ONNX_TENSOR_ELEMENT_DATA_TYPE_STRING, &input_tensor),
			fail);
	ORT_CHECK(api->FillStringTensor(input_tensor, &name, config.model->num_inputs),
			input_release_fail);

	input_tensors[0] = input_tensor;
	memset(output_tensors, 0, sizeof(output_tensors));

	ORT_CHECK(api->Run(config.model->session, NULL,
			input_names, (const OrtValue* const*)input_tensors, config.model->num_inputs,
			(const char* const*)config.model->output_names, config.model->num_outputs, output_tensors),
			input_release_fail); // the actual model inference

	// We only use the probability of the malicious class, which is
	// at index [DGA_MODEL_DEF.output_probs_index][DGA_MODEL_DEF.output_probs_dga_index].
	if (output_tensors[DGA_MODEL_DEF.output_probs_index]) {
		float* data;
		ORT_CHECK(api->GetTensorMutableData(output_tensors[DGA_MODEL_DEF.output_probs_index],
				(void**)&data),
				output_release_fail);
		// data size and type checked during initialization, this should be safe
		prob_dga = data[DGA_MODEL_DEF.output_probs_dga_index];
	}

output_release_fail:
	for (size_t i = 0; i < config.model->num_outputs; i++) api->ReleaseValue(output_tensors[i]);
input_release_fail:
	api->ReleaseValue(input_tensor);
fail:
	if (status) api->ReleaseStatus(status);
	return prob_dga * 100;
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

void load_model(const char *model_path)
{
	config.model = calloc(1, sizeof(*config.model));
	if (!config.model) return;

	if (model_context_init(model_path) != kr_ok()) {
		free(config.model);
		config.model = NULL;
		return;
	}
}

void free_model(void)
{
	if (!config.model) return;
	model_context_deinit();
	free(config.model);
}

KR_EXPORT
int dga_filter_setup(const char *model, kr_rule_tags_t tags, uint16_t threshold)
{
	config.tags = tags;
	config.threshold = threshold;

	int ret;
	load_model(model);
	if (!config.model) {
		ret = kr_error(EINVAL); // we don't know what's wrong
		goto fail;
	}

	return 0;
fail:
	if (config.model) {
		free_model();
		config.model = NULL;
	}
	kr_log_crit(DGA, "Initialization of shared DGA filter data failed.\n");
	load_attempted = true;
	return ret;
}

/// Ensure that the filter is loaded; return false if failed.
static bool ensure_loaded(void)
{
	if (config.model)
		return true;
	if (load_attempted)
		return false;

	kr_log_warning(DGA, "DGA filter not initialized from Lua, using hardcoded default.\n");
	int ret = dga_filter_setup("/home/dgad.onnx" , KR_RULE_TAGS_ALL, 31);// FIXME TMP
	return ret == kr_ok();
}

static void do_filter(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (!ensure_loaded())
		return;
	if (kr_request_unblocked(req))
		return;
	if (!req->qsource.addr)
		return;  // don't consider internal requests
	if (req->qsource.price_factor16 == 0)
		return;  // whitelisted
	if (qry->flags.CACHED) {
		return; // don't consider cached results
	}
	if (req->options.DGA_CHECKED) {
		return; // don't consider already checked requests
	}

	req->options.DGA_CHECKED = 1;

	// this logic comes from kr_rule_consume_tags()
	// Per-packet detection
	// _apply tags take precendence, and we store the last one
	kr_rule_tags_t const det_tags_apply = config.tags & req->rule_tags_apply;
	const bool det_do_apply = config.tags == KR_RULE_TAGS_ALL || det_tags_apply;
	// _audit: we fill everything if we're the very first action
	kr_rule_tags_t const det_tags_audit = config.tags & req->rule_tags_audit;
	const bool det_do_audit = det_tags_audit && !req->rule.action;

	if (!det_do_apply && !det_do_audit)
		return; // we save the expensive computations

	kr_rule_tags_t req_tags = det_do_apply ? det_tags_apply : det_tags_audit;

	float dga_prob = -1;

	char *label = get_label_before_suffix(qry->sname);
	if (label) {
		if (strlen(label) < DGA_BYPASS_MIN_SLD_LEN) {
			dga_prob = 0.0f;
		} else {
			dga_prob = get_model_inference(label);
		}
		free(label);
		label = NULL;
	}

	if (dga_prob <= config.threshold) {
		return;
	}

	kr_log_debug(DGA, "Malicious packet detected! (%f %%) %s\n",
			(dga_prob),
			(det_do_apply ? "Blocking." : "Auditing.")
	);

	if (det_do_apply) {
		req->rule.tags = req_tags; // .action is filled by _do_answer()
		kr_rule_do_answer(KR_RULE_SUB_NXDOMAIN, qry, pkt, qry->sname);
	} else {
		kr_assert(det_do_audit);
		req->rule.tags = req_tags;
		req->rule.action = KREQ_ACTION_AUDIT;
	}
}

static int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	do_filter(ctx, pkt);
	return ctx->state;
}

/// Remove mmapped file data if not used by other processes.
KR_EXPORT
int dga_filter_deinit(struct kr_module *self)
{
	free_model();
	config.model = NULL;
	return kr_ok();
}

KR_EXPORT
int dga_filter_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.produce = produce,
	};
	layer.data = module;
	module->layer = &layer;

	return kr_ok();
}

KR_MODULE_EXPORT(dga_filter)
