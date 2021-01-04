/* Copyright (C) Knot Resolver contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This module logs (query name, type) pairs which failed DNSSEC validation. */

#include <libknot/packet/pkt.h>
#include <libknot/dname.h>
#include <ccan/json/json.h>
#include <contrib/cleanup.h>

#include "daemon/engine.h"
#include "lib/layer.h"
#include "lib/generic/lru.h"

#ifdef LRU_REP_SIZE
 #define FREQUENT_COUNT LRU_REP_SIZE /* Size of frequent tables */
#else
 #define FREQUENT_COUNT  5000 /* Size of frequent tables */
#endif

/** @internal LRU hash of most frequent names. */
typedef lru_t(unsigned) namehash_t;

/** @internal Stats data structure. */
struct stat_data {
	namehash_t *frequent;
};

static int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	if (!(ctx->state & KR_STATE_FAIL)
	    || !ctx->req
	    || !ctx->req->current_query
	    || !ctx->req->current_query->flags.DNSSEC_BOGUS
	    || knot_wire_get_qdcount(pkt->wire) != 1)
		return ctx->state;

	auto_free char *qname_text = kr_dname_text(knot_pkt_qname(pkt));
	auto_free char *qtype_text = kr_rrtype_text(knot_pkt_qtype(pkt));

	kr_log_error("DNSSEC validation failure %s %s\n", qname_text, qtype_text);

	/* log of most frequent bogus queries */
	uint16_t type = knot_pkt_qtype(pkt);
	char key[sizeof(type) + KNOT_DNAME_MAXLEN];
	memcpy(key, &type, sizeof(type));
	int key_len = knot_dname_to_wire((uint8_t *)key + sizeof(type), knot_pkt_qname(pkt), KNOT_DNAME_MAXLEN);
	if (key_len >= 0) {
		struct kr_module *module = ctx->api->data;
		struct stat_data *data = module->data;
		unsigned *count = lru_get_new(data->frequent, key, key_len+sizeof(type), NULL);
		if (count)
			*count += 1;
	}

	return ctx->state;
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
	return dump_list(env, module, args, data->frequent);
}

KR_EXPORT
int bogus_log_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.consume = &consume,
	};
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
		{ &dump_frequent, "frequent", "List most frequent queries.", },
		{ NULL, NULL, NULL }
	};
	module->props = props;

	struct stat_data *data = calloc(1, sizeof(*data));
	if (!data) {
		return kr_error(ENOMEM);
	}
	module->data = data;
	lru_create(&data->frequent, FREQUENT_COUNT, NULL, NULL);
	return kr_ok();
}

KR_EXPORT
int bogus_log_deinit(struct kr_module *module)
{
	struct stat_data *data = module->data;
	if (data) {
		lru_free(data->frequent);
		free(data);
	}
	return kr_ok();
}

KR_MODULE_EXPORT(bogus_log)
