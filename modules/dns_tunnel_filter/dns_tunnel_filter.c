/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
*  SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdatomic.h>
#include "libblcnn.h"
#include "lib/kru.h"
#include "lib/kru-utils.h"
#include "lib/mmapped.h"
#include "lib/utils.h"
#include "lib/resolve.h"

enum { DNAME_SCALE_MULT = 2622 };

#define VERBOSE_LOG(...) kr_log_debug(TUNNEL, " | " __VA_ARGS__)

struct dns_tunnel_filter {
	size_t capacity;
	uint32_t instant_limit;
	uint32_t rate_limit;
	bool using_avx2;

	kru_price_t v4_prices[V4_PREFIXES_CNT];
	kru_price_t v6_prices[V6_PREFIXES_CNT];
	_Alignas(64) uint8_t kru[];
};
struct dns_tunnel_filter *dns_tunnel_filter = NULL;
struct mmapped dns_tunnel_filter_mmapped = {0};

bool load_attempted = false;

/// Config/state that's not suitable for mmapping.  TODO: name, etc?
struct {
	TorchModule net;
	kr_rule_tags_t tags;
} config = {0};


KR_EXPORT
int dns_tunnel_filter_setup(const char *nn_file, const char *mmap_file, kr_rule_tags_t tags,
		size_t capacity, uint32_t instant_limit, uint32_t rate_limit)
{
	if (dns_tunnel_filter)
		return kr_error(EALREADY); // we don't support reconfiguration for now

	config.tags = tags;

	int ret;
	config.net = load_model(nn_file);
	if (!config.net) {
		ret = kr_error(EINVAL); // we don't know what's wrong
		goto fail;
	}

	size_t capacity_log = 0;
	for (size_t c = capacity - 1; c > 0; c >>= 1) capacity_log++;

	size_t size = offsetof(struct dns_tunnel_filter, kru) + KRU.get_size(capacity_log);

	struct dns_tunnel_filter header = {
		.capacity = capacity,
		.instant_limit = instant_limit,
		.rate_limit = rate_limit,
		.using_avx2 = using_avx2()
	};

	size_t header_size = offsetof(struct dns_tunnel_filter, using_avx2) + sizeof(header.using_avx2);
	static_assert(  // no implicit padding up to .using_avx2
		offsetof(struct dns_tunnel_filter, using_avx2) ==
			sizeof(header.capacity) +
			sizeof(header.instant_limit) +
			sizeof(header.rate_limit),
		"detected padding with undefined data inside mmapped header");

	ret = mmapped_init(&dns_tunnel_filter_mmapped, mmap_file, size, &header, header_size);
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

		for (size_t i = 0; i < V4_PREFIXES_CNT; i++) {
			dns_tunnel_filter->v4_prices[i] = base_price / V4_RATE_MULT[i];
		}

		for (size_t i = 0; i < V6_PREFIXES_CNT; i++) {
			dns_tunnel_filter->v6_prices[i] = base_price / V6_RATE_MULT[i];
		}

		ret = mmapped_init_continue(&dns_tunnel_filter_mmapped);
		if (ret != 0) goto fail;

		kr_log_info(TUNNEL, "DNS tunnel filter initialized (%s).\n", (dns_tunnel_filter->using_avx2 ? "AVX2" : "generic"));
		return 0;
	} else if (ret == 0) {
		dns_tunnel_filter = dns_tunnel_filter_mmapped.mem;
		kr_log_info(TUNNEL, "Using existing DNS tunnel filter data (%s).\n", (dns_tunnel_filter->using_avx2 ? "AVX2" : "generic"));
		return 0;
	} // else fail

fail:
	if (config.net) {
		free_model(config.net);
		config.net = NULL;
	}
	kr_log_crit(TUNNEL, "Initialization of shared DNS tunnel filter data failed.\n");
	load_attempted = true;
	return ret;
}

/// Ensure that the filter is loaded; return false if failed.
static bool ensure_loaded(void)
{
	if (dns_tunnel_filter)
		return true;
	if (load_attempted)
		return false;

	kr_log_warning(TUNNEL, "Tunneling filter not initialized from Lua, using hardcoded default.\n");
	kr_rule_tags_t tags = 0;
	int ret = kr_rule_tag_add("tunnel", &tags);
	if (ret) return ret;
	ret = dns_tunnel_filter_setup("/home/vcunat/dev/nic-notes/vysocina/blcnn.pt", // FIXME TMP
					"dns_tunnel_filter", tags,
					(1 << 20), (1 << 8), (1 << 17));
	return ret == kr_ok();
}

static void do_filter(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (!ensure_loaded())
		return;
	if (!req->qsource.addr)
		return;  // don't consider internal requests
	if (req->qsource.price_factor16 == 0)
		return;  // whitelisted
	if (qry->flags.CACHED) {
		return; // don't consider cached results
	}

// this logic comes from kr_rule_consume_tags()
	// _apply tags take precendence, and we store the last one
	kr_rule_tags_t const tags_apply = config.tags & req->rule_tags_apply;
	const bool do_apply = config.tags == KR_RULE_TAGS_ALL || tags_apply;
	// _audit: we fill everything iff we're the very first action
	kr_rule_tags_t const tags_audit = config.tags & req->rule_tags_audit;
	const bool do_audit = tags_audit && !req->rule.action;
	if (!do_apply && !do_audit)
		return; // we save the expensive computations

	const uint32_t time_now = kr_now();
	uint32_t price_scale_factor = knot_dname_size(qry->sname) * DNAME_SCALE_MULT;

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
					* (uint64_t)dns_tunnel_filter->v6_prices[i] + (1ull<<31)) >> 32;
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
					* (uint64_t)dns_tunnel_filter->v4_prices[i] + (1ull<<31)) >> 32;
		}
		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)dns_tunnel_filter->kru, time_now,
				0, key, V4_PREFIXES, prices, V4_PREFIXES_CNT, NULL);
	}
	if (!limited_prefix) return;  // not limited

	uint8_t *packet = req->qsource.packet->wire;
	size_t packet_size = req->qsource.size;

	float tunnel_prob = predict_packet(config.net, packet, packet_size);
	
	if (tunnel_prob <= 0.95)
		return;
	kr_log_debug(TUNNEL, "Malicious packet detected! (%f %%) %s\n",
			(tunnel_prob - 0.95) * 100 * 20,
	      		(do_apply ? "Blocking." : "Auditing.")
	);

	if (do_apply) {
		kr_rule_do_answer(KR_RULE_SUB_NXDOMAIN, qry, pkt, qry->sname);
	} else {
		kr_assert(do_audit);
		req->rule.tags = tags_audit;
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
int dns_tunnel_filter_deinit(struct kr_module *self)
{
	free_model(config.net);
	mmapped_deinit(&dns_tunnel_filter_mmapped);
	dns_tunnel_filter = NULL;
	return kr_ok();
}

KR_EXPORT
int dns_tunnel_filter_init(struct kr_module *module) {
	static kr_layer_api_t layer = {
		.produce = produce,
	};
	layer.data = module;
	module->layer = &layer;

	return kr_ok();
}

KR_MODULE_EXPORT(dns_tunnel_filter)
