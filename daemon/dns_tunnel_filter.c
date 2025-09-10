/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
*  SPDX-License-Identifier: GPL-3.0-or-later
*/

#include "onnxruntime_c_api.h"
#include <stdatomic.h>
#include "daemon/session2.h"
#include "lib/mmapped.h"
#include "lib/utils.h"
#include "lib/resolve.h"
#include <math.h>
#include "daemon/udp_queue.h"
#include "lib/kru.h"

#include "dns_tunnel_filter.h"

#define V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define V4_PREFIXES_CNT (sizeof(V4_PREFIXES) / sizeof(*V4_PREFIXES))
#define V6_PREFIXES_CNT (sizeof(V6_PREFIXES) / sizeof(*V6_PREFIXES))
#define MAX_PREFIXES_CNT ((V4_PREFIXES_CNT > V6_PREFIXES_CNT) ? V4_PREFIXES_CNT : V6_PREFIXES_CNT)

#define DNAME_SCALE_FACTOR 25

#define NN_INPUT_DIMS 2
#define NN_FAIL_RETURN 0.0f
#define NN_PADDING_VALUE 256

#define MAX_PACKET_SIZE 300

#define VERBOSE_LOG(...) kr_log_debug(TUNNEL, " | " __VA_ARGS__)

#define ORT_CHECK(expr, label)  \
	do {                        \
		status = (expr);        \
		if (status) goto label; \
	} while (0)

struct nn_model_context{
	OrtEnv*       env;
	OrtSession*   session;
	OrtAllocator* allocator;
	char*         input_name;
	char*         output_name;
	size_t        num_inputs;
	size_t        num_outputs;

	OrtValue* input_tensor;
	int64_t *input_data;
};

struct dns_tunnel_filter {
	size_t capacity;
	uint32_t instant_limit;
	uint32_t rate_limit;
	uint32_t log_period;
	uint16_t slip;
	bool dry_run;
	bool using_avx2;
	struct nn_model_context *net;
	_Atomic uint32_t log_time;
	kru_price_t v4_prices[V4_PREFIXES_CNT];
	kru_price_t v6_prices[V6_PREFIXES_CNT];
	_Alignas(64) uint8_t kru[];
};
struct dns_tunnel_filter *dns_tunnel_filter = NULL;
struct mmapped dns_tunnel_filter_mmapped = {0};
bool dns_tunnel_filter_initialized = false;
/// return whether we're using optimized variant right now
static bool using_avx2(void)
{
	bool result = (KRU.initialize == KRU_AVX2.initialize);
	kr_require(result || KRU.initialize == KRU_GENERIC.initialize);
	return result;
}

void model_context_deinit(struct nn_model_context* ctx)
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

	if (ctx->output_name) {
		status = api->AllocatorFree(ctx->allocator, ctx->output_name);
		if (status) {
			api->ReleaseStatus(status);
			status = NULL;
		}
		ctx->output_name = NULL;
	}

	if (ctx->input_tensor) {
		api->ReleaseValue(ctx->input_tensor);
		ctx->input_tensor = NULL;
		ctx->input_data = NULL;
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

int prepare_input_tensor(struct nn_model_context* ctx)
{
	int is_tensor;
	int64_t dims[NN_INPUT_DIMS] = {1, MAX_PACKET_SIZE};
	OrtStatus* status = NULL;

	const OrtApi* api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	ORT_CHECK(api->CreateTensorAsOrtValue(ctx->allocator, dims, NN_INPUT_DIMS, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &(ctx->input_tensor)),
			fail);

	ORT_CHECK(api->GetTensorMutableData(ctx->input_tensor, (void**)&(ctx->input_data)),
			get_pointer_fail);

	ORT_CHECK(api->IsTensor(ctx->input_tensor, &is_tensor), fail);
	if (!is_tensor) goto fail;

	return 0;
get_pointer_fail:
	api->ReleaseValue(ctx->input_tensor);
fail:
	if (status) {
		kr_log_crit(TUNNEL, "prepare_input_tensor failed: %s\n", api->GetErrorMessage(status));
		api->ReleaseStatus(status);
	}
	return -1;
}

int model_context_init(struct nn_model_context* ctx, const char* model_path)
{
	OrtSessionOptions* session_options;
	OrtStatus* status = NULL;

	ctx->env = NULL;
	ctx->session = NULL;
	ctx->allocator = NULL;
	ctx->input_name = NULL;
	ctx->output_name = NULL;

	ctx->input_tensor = NULL;
	ctx->input_data = NULL;

	const OrtApi* api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	ORT_CHECK(api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "tunnel-detector", &(ctx->env)),
			fail);
	ORT_CHECK(api->CreateSessionOptions(&session_options),
			fail);

	ORT_CHECK(api->CreateSession(ctx->env, model_path, session_options, &(ctx->session)),
	 		fail);

	api->ReleaseSessionOptions(session_options);

	ORT_CHECK(api->GetAllocatorWithDefaultOptions(&(ctx->allocator)),
			fail);

	ORT_CHECK(api->SessionGetInputName(ctx->session, 0, ctx->allocator, &(ctx->input_name)),
			fail);
	ORT_CHECK(api->SessionGetOutputName(ctx->session, 0, ctx->allocator, &(ctx->output_name)),
			fail);
	ORT_CHECK(api->SessionGetInputCount(ctx->session, &(ctx->num_inputs)),
			fail);
	ORT_CHECK(api->SessionGetOutputCount(ctx->session, &(ctx->num_outputs)),
			fail);

	if (prepare_input_tensor(ctx)) goto fail;

	return kr_ok();

fail:
	if (status) {
		kr_log_crit(TUNNEL, "create_context failed: %s\n", api->GetErrorMessage(status));
		api->ReleaseStatus(status);
	}
	model_context_deinit(ctx);
	return kr_error(ENOMEM);
}

float get_model_inference(struct nn_model_context* ctx, uint8_t* data, size_t data_size)
{
	const OrtApi* api;
	OrtStatus* status = NULL;

	const char* input_names[] = {ctx->input_name};
	const char* output_names[] = {ctx->output_name};

	OrtValue* output_tensor = NULL;

	float* output_data;
	float e0, e1, sum, prob0;

	if (!ctx) return -1.0f;

	api = OrtGetApiBase()->GetApi(ORT_API_VERSION);

	for (size_t i = 0; i < data_size && i < MAX_PACKET_SIZE; i++) {
		ctx->input_data[i] = (int64_t)data[i];
	}
	for (size_t i = data_size; i < MAX_PACKET_SIZE; i++) {
		ctx->input_data[i] = 256;
	}

	ORT_CHECK(api->Run(ctx->session, NULL, input_names, (const OrtValue* const*)&(ctx->input_tensor), ctx->num_inputs, output_names, ctx->num_outputs,
			&output_tensor),
			fail);

	ORT_CHECK(api->GetTensorMutableData(output_tensor, (void**)&output_data),
			fail);

	e0 = expf(output_data[0]);
	e1 = expf(output_data[1]);

	sum = e0 + e1;
	prob0 = e0 / sum;

	return prob0;
fail:
	if (status) {
		kr_log_crit(TUNNEL, "get_model_inference failed: %s\n", api->GetErrorMessage(status));
		api->ReleaseStatus(status);
	}
	return 0.0f;
}

int dns_tunnel_filter_init(const char *mmap_file, size_t capacity, uint32_t instant_limit,
		uint32_t rate_limit, uint16_t slip, uint32_t log_period, bool dry_run)
{
	dns_tunnel_filter_initialized = true;
	size_t capacity_log = 0;
	for (size_t c = capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct dns_tunnel_filter, kru) + KRU.get_size(capacity_log);

	struct dns_tunnel_filter header = {
		.capacity = capacity,
		.instant_limit = instant_limit,
		.rate_limit = rate_limit,
		.log_period = log_period,
		.slip = slip,
		.dry_run = dry_run,
		.using_avx2 = using_avx2()
	};

	size_t header_size = offsetof(struct dns_tunnel_filter, using_avx2) + sizeof(header.using_avx2);
	static_assert(  // no padding up to .using_avx2
		offsetof(struct dns_tunnel_filter, using_avx2) ==
			sizeof(header.capacity) +
			sizeof(header.instant_limit) +
			sizeof(header.rate_limit) +
			sizeof(header.log_period) +
			sizeof(header.slip) +
			sizeof(header.dry_run),
		"detected padding with undefined data inside mmapped header");

	int ret = mmapped_init(&dns_tunnel_filter_mmapped, mmap_file, size, &header, header_size);
	if (ret == MMAPPED_WAS_FIRST) {
		kr_log_info(TUNNEL, "Initializing DNS tunnel filter...\n");

		dns_tunnel_filter = dns_tunnel_filter_mmapped.mem;

		const kru_price_t base_price = KRU_LIMIT / instant_limit;
		const kru_price_t max_decay = rate_limit > 1000ll * instant_limit ? base_price :
			(uint64_t) base_price * rate_limit / 1000;

		bool succ = KRU.initialize((struct kru *)dns_tunnel_filter->kru, capacity_log, max_decay);
		if (!succ) {
			dns_tunnel_filter = NULL;
			ret = kr_error(EINVAL);
			goto fail;
		}

		dns_tunnel_filter->log_time = kr_now() - log_period;

		for (size_t i = 0; i < V4_PREFIXES_CNT; i++) {
			dns_tunnel_filter->v4_prices[i] = base_price / V4_RATE_MULT[i];
		}

		for (size_t i = 0; i < V6_PREFIXES_CNT; i++) {
			dns_tunnel_filter->v6_prices[i] = base_price / V6_RATE_MULT[i];
		}

		dns_tunnel_filter->net = calloc(1, sizeof(struct nn_model_context));
		if (!dns_tunnel_filter->net) goto fail;

		ret = model_context_init(dns_tunnel_filter->net, "/home/hsabacky/code/knot-resolver/daemon/blcnn.onnx");
		if (ret) goto net_fail;

		ret = mmapped_init_continue(&dns_tunnel_filter_mmapped);
		if (ret != 0) goto net_fail;

		kr_log_info(TUNNEL, "DNS tunnel filter initialized (%s).\n", (dns_tunnel_filter->using_avx2 ? "AVX2" : "generic"));
		return 0;
	} else if (ret == 0) {
		dns_tunnel_filter = dns_tunnel_filter_mmapped.mem;
		kr_log_info(TUNNEL, "Using existing DNS tunnel filter data (%s).\n", (dns_tunnel_filter->using_avx2 ? "AVX2" : "generic"));
		return 0;
	} // else fail

net_fail:
	model_context_deinit(dns_tunnel_filter->net);
	free(dns_tunnel_filter->net);
fail:
	kr_log_crit(TUNNEL, "Initialization of shared DNS tunnel filter data failed.\n");
	return ret;
}

void dns_tunnel_filter_deinit(void)
{
	model_context_deinit(dns_tunnel_filter->net);
	free(dns_tunnel_filter->net);
	dns_tunnel_filter->net = NULL;
	mmapped_deinit(&dns_tunnel_filter_mmapped);
	dns_tunnel_filter = NULL;
}

bool dns_tunnel_filter_request_begin(struct kr_request *req)
{
	if (!dns_tunnel_filter) return false;
	if (!req->qsource.addr)
		return false;  // don't consider internal requests
	if (req->qsource.price_factor16 == 0)
		return false;  // whitelisted
	if (!req->current_query)
		return false;
	if (req->current_query->flags.CACHED == true)
		return false;  // don't consider cached results
	if (!req->current_query->sname)
		return false;

	const uint32_t time_now = kr_now();
	uint32_t price_scale_factor = (strlen((char *)req->current_query->sname) << 16)/ DNAME_SCALE_FACTOR;

	// classify
	_Alignas(16) uint8_t key[16] = {0, };
	uint8_t limited_prefix;
	if (req->qsource.addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)req->qsource.addr;
		memcpy(key, &ipv6->sin6_addr, 16);

		// compute adjusted prices, using standard rounding
		kru_price_t prices[V6_PREFIXES_CNT];
		for (int i = 0; i < V6_PREFIXES_CNT; ++i) {
			prices[i] = (req->qsource.price_factor16 * (uint64_t)price_scale_factor
					* (uint64_t)dns_tunnel_filter->v6_prices[i] + (1<<15)) >> 32;
		}
		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)dns_tunnel_filter->kru, time_now,
				1, key, V6_PREFIXES, prices, V6_PREFIXES_CNT, NULL);
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)req->qsource.addr;
		memcpy(key, &ipv4->sin_addr, 4);  // TODO append port?

		// compute adjusted prices, using standard rounding
		kru_price_t prices[V4_PREFIXES_CNT];
		for (int i = 0; i < V4_PREFIXES_CNT; ++i) {
			prices[i] = (req->qsource.price_factor16 * (uint64_t)price_scale_factor
					* (uint64_t)dns_tunnel_filter->v4_prices[i] + (1<<15)) >> 32;
		}
		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)dns_tunnel_filter->kru, time_now,
				0, key, V4_PREFIXES, prices, V4_PREFIXES_CNT, NULL);
	}
	if (!limited_prefix) return false;  // not limited

	uint8_t *packet = req->qsource.packet->wire;
	size_t packet_size = req->qsource.size;

	float tunnel_prob = get_model_inference(dns_tunnel_filter->net, packet, packet_size);

	if (tunnel_prob > 0.95) {
		kr_log_info(TUNNEL, "Malicious packet detected! (%f %%)\n", (tunnel_prob - 0.95) * 100 * 20);
		req->options.NO_ANSWER = true;
		req->state = KR_STATE_FAIL;
		return true;
	} else {
		return false;
	}
}
