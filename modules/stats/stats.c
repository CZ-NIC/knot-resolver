/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file stats.c
 * @brief Storage for various counters and metrics from query resolution.
 *
 * You can either reuse this module to compute statistics or store custom metrics
 * in it via the extensions.
 */

#include <libknot/packet/pkt.h>
#include <libknot/packet/wire.h>
#include <libknot/descriptor.h>
#include <ccan/json/json.h>
#include <contrib/cleanup.h>
#include <arpa/inet.h>
#include <lua.h>

#include "lib/layer/iterate.h"
#include "lib/rplan.h"
#include "lib/module.h"
#include "lib/layer.h"
#include "lib/resolve.h"

/* Defaults */
#define VERBOSE_MSG(qry, ...) QRVERBOSE(qry, "stat",  __VA_ARGS__)
#define FREQUENT_PSAMPLE  10 /* Sampling rate, 1 in N */
#ifdef LRU_REP_SIZE
 #define FREQUENT_COUNT LRU_REP_SIZE /* Size of frequent tables */
#else
 #define FREQUENT_COUNT  5000 /* Size of frequent tables */
#endif
#ifndef UPSTREAMS_COUNT
 #define UPSTREAMS_COUNT  512 /* Size of recent upstreams */
#endif

/** @cond internal Fixed-size map of predefined metrics. */
#define CONST_METRICS(X) \
	X(answer,total) X(answer,noerror) X(answer,nodata) X(answer,nxdomain) X(answer,servfail) \
	X(answer,cached) X(answer,1ms) X(answer,10ms) X(answer,50ms) X(answer,100ms) \
	X(answer,250ms) X(answer,500ms) X(answer,1000ms) X(answer,1500ms) X(answer,slow) \
	X(answer,aa) X(answer,tc) X(answer,rd) X(answer,ra) X(answer, ad) X(answer,cd) \
	X(answer,edns0) X(answer,do) \
	X(query,edns) X(query,dnssec) \
	X(request,total) X(request,udp) X(request,tcp) \
	X(request,dot) X(request,doh) X(request,internal) \
	X(const,end)

enum const_metric {
	#define X(a,b) metric_ ## a ## _ ## b,
	CONST_METRICS(X)
	#undef X
};
struct const_metric_elm {
	const char *key;
	size_t val;
};
static struct const_metric_elm const_metrics[] = {
	#define X(a,b) [metric_ ## a ## _ ## b] = { #a "." #b, 0 },
	CONST_METRICS(X)
	#undef X
};
/** @endcond */

/** @internal LRU hash of most frequent names. */
typedef lru_t(unsigned) namehash_t;
typedef array_t(struct sockaddr_in6) addrlist_t;

/** @internal Stats data structure. */
struct stat_data {
	map_t map;
	struct {
		namehash_t *frequent;
	} queries;
	struct {
		addrlist_t q;
		size_t head;
	} upstreams;
};

/** @internal We don't store/publish port, repurpose it for RTT instead. */
#define sin6_rtt sin6_port

/** @internal Add to const map counter */
static inline void stat_const_add(struct stat_data *data, enum const_metric key, ssize_t incr)
{
	const_metrics[key].val += incr;
}

static int collect_answer(struct stat_data *data, knot_pkt_t *pkt)
{
	stat_const_add(data, metric_answer_total, 1);
	/* Count per-rcode */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
		if (knot_wire_get_ancount(pkt->wire) > 0)
			stat_const_add(data, metric_answer_noerror, 1);
		else
			stat_const_add(data, metric_answer_nodata, 1);
	break;
	case KNOT_RCODE_NXDOMAIN: stat_const_add(data, metric_answer_nxdomain, 1); break;
	case KNOT_RCODE_SERVFAIL: stat_const_add(data, metric_answer_servfail, 1); break;
	default: break;
	}

	return kr_ok();
}

static inline int collect_key(char *key, const knot_dname_t *name, uint16_t type)
{
	memcpy(key, &type, sizeof(type));
	int key_len = knot_dname_to_wire((uint8_t *)key + sizeof(type), name, KNOT_DNAME_MAXLEN);
	if (key_len < 0) {
		return kr_error(key_len);
	}
	return key_len + sizeof(type);
}

static void collect_sample(struct stat_data *data, struct kr_rplan *rplan, knot_pkt_t *pkt)
{
	/* Sample key = {[2] type, [1-255] owner} */
	char key[sizeof(uint16_t) + KNOT_DNAME_MAXLEN];
	for (size_t i = 0; i < rplan->resolved.len; ++i) {
		/* Sample queries leading to iteration */
		struct kr_query *qry = rplan->resolved.at[i];
		if (qry->flags.CACHED) {
			continue;
		}
		/* Consider 1 in N for frequent sampling.
		 * TODO: redesign the sampling approach. */
		if (kr_rand_coin(1, FREQUENT_PSAMPLE)) {
			int key_len = collect_key(key, qry->sname, qry->stype);
			if (key_len < 0) {
				assert(false);
				continue;
			}
			unsigned *count = lru_get_new(data->queries.frequent, key, key_len, NULL);
			if (count)
				*count += 1;
		}
	}
}

static int collect_rtt(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (qry->flags.CACHED || !req->upstream.transport) {
		return ctx->state;
	}

	/* Push address and RTT to the ring buffer head */
	struct kr_module *module = ctx->api->data;
	struct stat_data *data = module->data;

	/* Socket address is encoded into sockaddr_in6 struct that
	 * unions with sockaddr_in and differ in sa_family */
	struct sockaddr_in6 *e = &data->upstreams.q.at[data->upstreams.head];
	const struct sockaddr *src = &req->upstream.transport->address.ip;
	switch (src->sa_family) {
	case AF_INET:  memcpy(e, src, sizeof(struct sockaddr_in)); break;
	case AF_INET6: memcpy(e, src, sizeof(struct sockaddr_in6)); break;
	default: return ctx->state;
	}
	/* Replace port number with the RTT information (cap is UINT16_MAX milliseconds) */
	e->sin6_rtt = req->upstream.rtt;

	/* Advance ring buffer head */
	data->upstreams.head = (data->upstreams.head + 1) % UPSTREAMS_COUNT;
	return ctx->state;
}

static int collect_transport(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	struct kr_module *module = ctx->api->data;
	struct stat_data *data = module->data;

	stat_const_add(data, metric_request_total, 1);
	if (req->qsource.dst_addr == NULL) {
		stat_const_add(data, metric_request_internal, 1);
		return ctx->state;
	}

	/**
	 * Count each transport only once,
	 * i.e. DoT does not count as TCP.
	 */
	if (req->qsource.flags.http)
		stat_const_add(data, metric_request_doh, 1);
	else if (req->qsource.flags.tls)
		stat_const_add(data, metric_request_dot, 1);
	else if (req->qsource.flags.tcp)
		stat_const_add(data, metric_request_tcp, 1);
	else
		stat_const_add(data, metric_request_udp, 1);
	return ctx->state;
}

static int collect(kr_layer_t *ctx)
{
	struct kr_request *param = ctx->req;
	struct kr_module *module = ctx->api->data;
	struct kr_rplan *rplan = &param->rplan;
	struct stat_data *data = module->data;

	/* Collect data on final answer */
	collect_answer(data, param->answer);
	collect_sample(data, rplan, param->answer);
	/* Count cached and unresolved */
	if (rplan->resolved.len > 0) {
		/* Histogram of answer latency. */
		struct kr_query *first = rplan->resolved.at[0];
		uint64_t elapsed = kr_now() - first->timestamp_mono;
		if (elapsed <= 1) {
			stat_const_add(data, metric_answer_1ms, 1);
		} else if (elapsed <= 10) {
			stat_const_add(data, metric_answer_10ms, 1);
		} else if (elapsed <= 50) {
			stat_const_add(data, metric_answer_50ms, 1);
		} else if (elapsed <= 100) {
			stat_const_add(data, metric_answer_100ms, 1);
		} else if (elapsed <= 250) {
			stat_const_add(data, metric_answer_250ms, 1);
		} else if (elapsed <= 500) {
			stat_const_add(data, metric_answer_500ms, 1);
		} else if (elapsed <= 1000) {
			stat_const_add(data, metric_answer_1000ms, 1);
		} else if (elapsed <= 1500) {
			stat_const_add(data, metric_answer_1500ms, 1);
		} else {
			stat_const_add(data, metric_answer_slow, 1);
		}
		/* Observe the final query. */
		struct kr_query *last = kr_rplan_last(rplan);
		stat_const_add(data, metric_answer_cached, last->flags.CACHED);
	}

	/* Keep stats of all response header flags;
	 * these don't return bool, so that's why we use !! */
	stat_const_add(data, metric_answer_aa, !!knot_wire_get_aa(param->answer->wire));
	stat_const_add(data, metric_answer_tc, !!knot_wire_get_tc(param->answer->wire));
	stat_const_add(data, metric_answer_rd, !!knot_wire_get_rd(param->answer->wire));
	stat_const_add(data, metric_answer_ra, !!knot_wire_get_ra(param->answer->wire));
	stat_const_add(data, metric_answer_ad, !!knot_wire_get_ad(param->answer->wire));
	stat_const_add(data, metric_answer_cd, !!knot_wire_get_cd(param->answer->wire));

	/* EDNS0 stats */
	stat_const_add(data, metric_answer_edns0, knot_pkt_has_edns(param->answer));
	stat_const_add(data, metric_answer_do, knot_pkt_has_dnssec(param->answer));

	/* Query parameters and transport mode */
	/*
		DEPRECATED
		use new names metric_answer_edns0 and metric_answer_do
	*/
	stat_const_add(data, metric_query_edns, knot_pkt_has_edns(param->answer));
	stat_const_add(data, metric_query_dnssec, knot_pkt_has_dnssec(param->answer));

	return ctx->state;
}

/**
 * Set nominal value of a key.
 *
 * Input:  { key, val }
 *
 */
static char* stats_set(void *env, struct kr_module *module, const char *args)
{
	if (args == NULL)
		return NULL;

	struct stat_data *data = module->data;

	auto_free char *pair = strdup(args);
	char *val = strchr(pair, ' ');
	if (val) {
		*val = '\0';
		size_t number = strtoul(val + 1, NULL, 10);
		for (unsigned i = 0; i < metric_const_end; ++i) {
			if (strcmp(const_metrics[i].key, pair) == 0) {
				const_metrics[i].val = number;
				return NULL;
			}
		}
		map_set(&data->map, pair, (void *)number);
	}

	return NULL;
}

/**
 * Retrieve metrics by key.
 *
 * Input:  string key
 * Output: number value
 */
static char* stats_get(void *env, struct kr_module *module, const char *args)
{
	if (args == NULL)
		return NULL;

	struct stat_data *data = module->data;

	/* Expecting CHAR_BIT to be 8, this is a safe bet */
	char *ret = malloc(3 * sizeof(size_t) + 2);
	if (!ret) {
		return NULL;
	}

	/* Check if it exists in const map. */
	for (unsigned i = 0; i < metric_const_end; ++i) {
		if (strcmp(const_metrics[i].key, args) == 0) {
			sprintf(ret, "%zu", const_metrics[i].val);
			return ret;
		}
	}
	/* Check in variable map */
	if (!map_contains(&data->map, args)) {
		free(ret);
		return NULL;
	}
	void *val = map_get(&data->map, args);
	sprintf(ret, "%zu", (size_t) val);
	return ret;
}

static int list_entry(const char *key, void *val, void *baton)
{
	JsonNode *root = baton;
	size_t number = (size_t) val;
	json_append_member(root, key, json_mknumber(number));
	return 0;
}

/**
 * List observed metrics.
 *
 * Output: { key: val, ... }
 */
static char* stats_list(void *env, struct kr_module *module, const char *args)
{
	struct stat_data *data = module->data;
	JsonNode *root = json_mkobject();
	/* Walk const metrics map */
	size_t args_len = args ? strlen(args) : 0;
	for (unsigned i = 0; i < metric_const_end; ++i) {
		struct const_metric_elm *elm = &const_metrics[i];
		if (!args || strncmp(elm->key, args, args_len) == 0) {
			json_append_member(root, elm->key, json_mknumber(elm->val));
		}
	}
	map_walk_prefixed(&data->map, (args_len > 0) ? args : "", list_entry, root);
	char *ret = json_encode(root);
	json_delete(root);
	return ret;
}

/** @internal Helper for dump_list: add a single namehash_t item to JSON. */
static enum lru_apply_do dump_value(const char *key, uint len, unsigned *val, void *baton)
{
	uint16_t key_type = 0;
	/* Extract query name, type and counter */
	memcpy(&key_type, key, sizeof(key_type));
	KR_DNAME_GET_STR(key_name, (uint8_t *)key + sizeof(key_type));
	KR_RRTYPE_GET_STR(type_str, key_type);

	/* Convert to JSON object */
	JsonNode *json_val = json_mkobject();
	json_append_member(json_val, "count", json_mknumber(*val));
	json_append_member(json_val, "name",  json_mkstring(key_name));
	json_append_member(json_val, "type",  json_mkstring(type_str));
	json_append_element((JsonNode *)baton, json_val);
	return LRU_APPLY_DO_NOTHING; // keep the item
}
/**
 * List frequent names.
 *
 * Output: [{ count: <counter>, name: <qname>, type: <qtype>}, ... ]
 */
static char* dump_list(void *env, struct kr_module *module, const char *args, namehash_t *table)
{
	if (!table) {
		return NULL;
	}
	JsonNode *root = json_mkarray();
	lru_apply(table, dump_value, root);
	char *ret = json_encode(root);
	json_delete(root);
	return ret;
}

static char* dump_frequent(void *env, struct kr_module *module, const char *args)
{
	struct stat_data *data = module->data;
	return dump_list(env, module, args, data->queries.frequent);
}

static char* clear_frequent(void *env, struct kr_module *module, const char *args)
{
	struct stat_data *data = module->data;
	lru_reset(data->queries.frequent);
	return NULL;
}

static char* dump_upstreams(void *env, struct kr_module *module, const char *args)
{
	struct stat_data *data = module->data;
	if (!data) {
		return NULL;
	}

	/* Walk the ring backwards until AF_UNSPEC or we hit head. */
	JsonNode *root = json_mkobject();
	size_t head = data->upstreams.head;
	for (size_t i = 1; i < UPSTREAMS_COUNT; ++i) {
		size_t h = (UPSTREAMS_COUNT + head - i) % UPSTREAMS_COUNT;
		struct sockaddr_in6 *e = &data->upstreams.q.at[h];
		if (e->sin6_family == AF_UNSPEC) {
			break;
		}
		/* Convert address to string */
		char addr_str[INET6_ADDRSTRLEN];
		const char *ret = inet_ntop(e->sin6_family, kr_inaddr((const struct sockaddr *)e), addr_str, sizeof(addr_str));
		if (!ret) {
			break;
		}
		/* Append to map with an array encoding RTTs */
		JsonNode *json_val = json_find_member(root, addr_str);
		if (!json_val) {
			json_val = json_mkarray();
			json_append_member(root, addr_str, json_val);
		}
		json_append_element(json_val, json_mknumber(e->sin6_rtt));
	}

	/* Encode and return */
	char *ret = json_encode(root);
	json_delete(root);
	return ret;
}

KR_EXPORT
int stats_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.consume = &collect_rtt,
		.finish = &collect,
		.begin = &collect_transport,
	};
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	    { &stats_set,     "set", "Set {key, val} metrics.", },
	    { &stats_get,     "get", "Get metrics for given key.", },
	    { &stats_list,    "list", "List observed metrics.", },
	    { &dump_frequent, "frequent", "List most frequent queries.", },
	    { &clear_frequent,"clear_frequent", "Clear frequent queries log.", },
	    { &dump_upstreams,  "upstreams", "List recently seen authoritatives.", },
	    { NULL, NULL, NULL }
	};
	module->props = props;

	struct stat_data *data = malloc(sizeof(*data));
	if (!data) {
		return kr_error(ENOMEM);
	}
	memset(data, 0, sizeof(*data));
	data->map = map_make(NULL);
	module->data = data;
	lru_create(&data->queries.frequent, FREQUENT_COUNT, NULL, NULL);
	/* Initialize ring buffer of recently visited upstreams */
	array_init(data->upstreams.q);
	if (array_reserve(data->upstreams.q, UPSTREAMS_COUNT) != 0) {
		return kr_error(ENOMEM);
	}
	data->upstreams.q.len = UPSTREAMS_COUNT; /* signify we use the entries */
	for (size_t i = 0; i < UPSTREAMS_COUNT; ++i) {
		data->upstreams.q.at[i].sin6_family = AF_UNSPEC;
	}
	return kr_ok();
}

KR_EXPORT
int stats_deinit(struct kr_module *module)
{
	struct stat_data *data = module->data;
	if (data) {
		map_clear(&data->map);
		lru_free(data->queries.frequent);
		array_clear(data->upstreams.q);
		free(data);
	}
	return kr_ok();
}

KR_MODULE_EXPORT(stats)

#undef VERBOSE_MSG
