/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file hints.h
 * @brief Constructed zone cut from the hosts-like file, see @zonecut.h
 *
 * The module provides an override for queried address records.
 */

#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/aaaa.h>
#include <ccan/json/json.h>
#include <ucw/mempool.h>

#include "daemon/engine.h"
#include "lib/zonecut.h"
#include "lib/module.h"
#include "lib/layer.h"

/* Defaults */
#define DEFAULT_FILE "/etc/hosts"
#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "hint",  fmt)

/* Structure for reverse search (address to domain) */
struct rev_search_baton {
	knot_pkt_t *pkt;
	const knot_dname_t *name;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} addr;
	size_t addr_len;
};

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int put_answer(knot_pkt_t *pkt, knot_rrset_t *rr)
{
	int ret = 0;
	if (!knot_rrset_empty(rr)) {
		/* Update packet question */
		if (!knot_dname_is_equal(knot_pkt_qname(pkt), rr->owner)) {
			kr_pkt_recycle(pkt);
			knot_pkt_put_question(pkt, rr->owner, rr->rclass, rr->type);
		}
		/* Append to packet */
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rr, KNOT_PF_FREE);
	} else {
		ret = kr_error(ENOENT);
	}
	/* Clear RR if failed */
	if (ret != 0) {
		knot_rrset_clear(rr, &pkt->mm);
	}
	return ret;
}

static int find_reverse(const char *k, void *v, void *baton)
{
	const knot_dname_t *domain = (const knot_dname_t *)k;
	pack_t *addr_set = (pack_t *)v;
	struct rev_search_baton *search = baton;
	/* Check if it matches any of the addresses. */
	bool matches = false;
	uint8_t *addr = pack_head(*addr_set);
	while (!matches && addr != pack_tail(*addr_set)) {
		size_t len = pack_obj_len(addr);
		void *addr_val = pack_obj_val(addr);
		matches = (len == search->addr_len && memcmp(addr_val, (void *)&search->addr, len) == 0);
		addr = pack_obj_next(addr);
	}
	/* Synthesise PTR record */
	if (!matches) {
		return 0;
	}
	knot_pkt_t *pkt = search->pkt;
	knot_dname_t *qname = knot_dname_copy(search->name, &pkt->mm);
	knot_rrset_t rr;
	knot_rrset_init(&rr, qname, KNOT_RRTYPE_PTR, KNOT_CLASS_IN);
	knot_rrset_add_rdata(&rr, domain, knot_dname_size(domain), 0, &pkt->mm);
	/* Insert into packet */
	int ret = put_answer(pkt, &rr);
	if (ret == 0) {
		return 1;
	}
	return ret;
}

static inline uint8_t label2num(const uint8_t **src, int base)
{
	uint8_t ret = strtoul((const char *)(*src + 1), NULL, base) & 0xff; /* ord(0-64) => labels are separators */
	*src = knot_wire_next_label(*src, NULL);
	return ret;
}

static int satisfy_reverse(struct kr_zonecut *hints, knot_pkt_t *pkt, struct kr_query *qry)
{
	struct rev_search_baton baton = {
		.pkt = pkt,
		.name = qry->sname,
		.addr_len = sizeof(struct in_addr)
	};
	/* Check if it is IPv6/IPv4 query. */
	size_t need_labels = baton.addr_len;
	if (knot_dname_in((const uint8_t *)"\3ip6\4arpa", qry->sname)) {
		baton.addr_len = sizeof(struct in6_addr);
		need_labels = baton.addr_len * 2; /* Each label is a nibble */
	}
	/* Make address from QNAME (reverse order). */
	int labels = knot_dname_labels(qry->sname, NULL);
	if (labels != need_labels + 2) {
		return kr_error(EINVAL);
	}
	const uint8_t *src = qry->sname;
	uint8_t *dst = (uint8_t *)&baton.addr.ip4 + baton.addr_len - 1;
	for (size_t i = 0; i < baton.addr_len; ++i) {
		if (baton.addr_len == sizeof(struct in_addr)) { /* IPv4, 1 label = 1 octet */
			*dst = label2num(&src, 10);
		} else { /* IPv4, 1 label = 1 nibble */
			*dst = label2num(&src, 16);
			*dst |= label2num(&src, 16) << 4;
		}
		dst -= 1;
	}
	/* Try to find matching domains. */
	int ret = map_walk(&hints->nsset, find_reverse, &baton);
	if (ret > 0) {
		return kr_ok(); /* Found */
	}
	return kr_error(ENOENT);
}

static int satisfy_forward(struct kr_zonecut *hints, knot_pkt_t *pkt, struct kr_query *qry)
{
	/* Find a matching name */
	pack_t *addr_set = kr_zonecut_find(hints, qry->sname);
	if (!addr_set || addr_set->len == 0) {
		return kr_error(ENOENT);
	}
	knot_dname_t *qname = knot_dname_copy(qry->sname, &pkt->mm);
	knot_rrset_t rr;
	knot_rrset_init(&rr, qname, qry->stype, qry->sclass);
	size_t family_len = sizeof(struct in_addr);
	if (rr.type == KNOT_RRTYPE_AAAA) {
		family_len = sizeof(struct in6_addr);
	}

	/* Append address records from hints */
	uint8_t *addr = pack_head(*addr_set);
	while (addr != pack_tail(*addr_set)) {
		size_t len = pack_obj_len(addr);
		void *addr_val = pack_obj_val(addr);
		if (len == family_len) {
			knot_rrset_add_rdata(&rr, addr_val, len, 0, &pkt->mm);
		}
		addr = pack_obj_next(addr);
	}

	return put_answer(pkt, &rr);
}

static int query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	if (!qry || ctx->state & (KNOT_STATE_FAIL)) {
		return ctx->state;
	}

	struct kr_module *module = ctx->api->data;
	struct kr_zonecut *hint_map = module->data;
	switch(qry->stype) {
	case KNOT_RRTYPE_A:
	case KNOT_RRTYPE_AAAA: /* Find forward record hints */
		if (satisfy_forward(hint_map, pkt, qry) != 0)
			return ctx->state;
		break;
	case KNOT_RRTYPE_PTR: /* Find PTR record */
		if (satisfy_reverse(hint_map, pkt, qry) != 0)
			return ctx->state;
		break;
	default:
		return ctx->state; /* Ignore */
	}

	DEBUG_MSG(qry, "<= answered from hints\n");
	qry->flags &= ~QUERY_DNSSEC_WANT; /* Never authenticated */
	qry->flags |= QUERY_CACHED|QUERY_NO_MINIMIZE;
	pkt->parsed = pkt->size;
	knot_wire_set_qr(pkt->wire);
	return KNOT_STATE_DONE;
}

static int parse_addr_str(struct sockaddr_storage *sa, const char *addr)
{
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	return sockaddr_set(sa, family, addr, 0);
}

static int add_pair(struct kr_zonecut *hints, const char *name, const char *addr)
{
	/* Build key */
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(key, name, sizeof(key))) {
		return kr_error(EINVAL);
	}

	/* Parse address string */
	struct sockaddr_storage ss;
	if (parse_addr_str(&ss, addr) != 0) {
		return kr_error(EINVAL);
	}

	/* Build rdata */
	size_t addr_len = 0;
	uint8_t *raw_addr = sockaddr_raw(&ss, &addr_len);
	knot_rdata_t rdata[knot_rdata_array_size(addr_len)];
	knot_rdata_init(rdata, addr_len, raw_addr, 0);

	return kr_zonecut_add(hints, key, rdata);
}

static int load_map(struct kr_zonecut *hints, FILE *fp)
{
	size_t line_len = 0;
	size_t count = 0;
	auto_free char *line = NULL;

	while(getline(&line, &line_len, fp) > 0) {
		char *saveptr = NULL;
		char *tok = strtok_r(line, " \t\r", &saveptr);
		if (tok == NULL || strchr(tok, '#') || strlen(tok) == 0) {
			continue;
		}
		char *name_tok = strtok_r(NULL, " \t\n", &saveptr);
		while (name_tok != NULL) {
			if (add_pair(hints, name_tok, tok) == 0) {
				count += 1;
			}
			name_tok = strtok_r(NULL, " \t\n", &saveptr);
		}
	}

	DEBUG_MSG(NULL, "loaded %zu hints\n", count);
	return kr_ok();
}

static int load(struct kr_module *module, const char *path)
{
	auto_fclose FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		DEBUG_MSG(NULL, "reading '%s' failed: %s\n", path, strerror(errno));
		return kr_error(errno);
	} else {
		DEBUG_MSG(NULL, "reading '%s'\n", path);
	}

	/* Create pool and copy itself */
	mm_ctx_t _pool = {
		.ctx = mp_new(4096),
		.alloc = (mm_alloc_t) mp_alloc
	};
	mm_ctx_t *pool = mm_alloc(&_pool, sizeof(*pool));
	if (!pool) {
		return kr_error(ENOMEM);
	}
	memcpy(pool, &_pool, sizeof(*pool));

	/* Load file to map */
	struct kr_zonecut *hints = mm_alloc(pool, sizeof(*hints));
	kr_zonecut_init(hints, (const uint8_t *)(""), pool);
	module->data = hints;
	return load_map(hints, fp);
}

static void unload(struct kr_module *module)
{
	struct kr_zonecut *hints = module->data;
	if (hints) {
		kr_zonecut_deinit(hints);
		mp_delete(hints->pool->ctx);
		module->data = NULL;
	}
}

/**
 * Set name => address hint.
 *
 * Input:  { name, address }
 * Output: { result: bool }
 *
 */
static char* hint_set(void *env, struct kr_module *module, const char *args)
{
	struct kr_zonecut *hints = module->data;
	auto_free char *args_copy = strdup(args);

	int ret = -1;
	char *addr = strchr(args_copy, ' ');
	if (addr) {
		*addr = '\0';
		ret = add_pair(hints, args_copy, addr + 1);
	}

	char *result = NULL;
	asprintf(&result, "{ \"result\": %s", ret == 0 ? "true" : "false");
	return result;
}

/** @internal Pack address list into JSON array. */
static JsonNode *pack_addrs(pack_t *pack)
{
	char buf[SOCKADDR_STRLEN];
	JsonNode *root = json_mkarray();
	uint8_t *addr = pack_head(*pack);
	while (addr != pack_tail(*pack)) {
		size_t len = pack_obj_len(addr);
		int family = len == sizeof(struct in_addr) ? AF_INET : AF_INET6;
		if (!inet_ntop(family, pack_obj_val(addr), buf, sizeof(buf))) {
			break;
		}
		json_append_element(root, json_mkstring(buf));
		addr = pack_obj_next(addr);
	}
	return root;
}

/**
 * Retrieve address hint for given name.
 *
 * Input:  name
 * Output: { address1, address2, ... }
 */
static char* hint_get(void *env, struct kr_module *module, const char *args)
{
	struct kr_zonecut *hints = module->data;
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	pack_t *pack = NULL;
	if (knot_dname_from_str(key, args, sizeof(key))) {
		pack = kr_zonecut_find(hints, key);
	}
	if (!pack || pack->len == 0) {
		return NULL;
	}

	char *result = NULL;
	JsonNode *root = pack_addrs(pack);
	if (root) {
		result = json_encode(root);
		json_delete(root);
	}
	return result;
}

/** Retrieve hint list. */
static int pack_hint(const char *k, void *v, void *baton)
{
	char nsname_str[KNOT_DNAME_MAXLEN] = {'\0'};
	knot_dname_to_str(nsname_str, (const uint8_t *)k, sizeof(nsname_str));
	JsonNode *root_node = baton;
	JsonNode *addr_list = pack_addrs((pack_t *)v);
	if (!addr_list) {
		return kr_error(ENOMEM);
	}
	json_append_member(root_node, nsname_str, addr_list);
	return kr_ok();
}

static void unpack_hint(struct kr_zonecut *root_hints, JsonNode *table, const char *name)
{
	JsonNode *node = NULL;
	json_foreach(node, table) {
		switch(node->tag) {
		case JSON_STRING: add_pair(root_hints, name ? name : node->key, node->string_); break;
		case JSON_ARRAY: unpack_hint(root_hints, node, name ? name : node->key); break;
		default: continue;
		}
	}
}

/**
 * Get/set root hints set.
 *
 * Input:  { name: [addr_list], ... }
 * Output: current list
 *
 */
static char* hint_root(void *env, struct kr_module *module, const char *args)
{
	struct engine *engine = env;
	struct kr_context *ctx = &engine->resolver;
	struct kr_zonecut *root_hints = &ctx->root_hints;
	/* Replace root hints if parameter is set */
	if (args && strlen(args) > 0) {
		JsonNode *root_node = json_decode(args);
		kr_zonecut_set(root_hints, (const uint8_t *)"");
		unpack_hint(root_hints, root_node, NULL);
		json_delete(root_node);
	}
	/* Return current root hints */
	char *result = NULL;
	JsonNode *root_node = json_mkobject();
	if (map_walk(&root_hints->nsset, pack_hint, root_node) == 0) {
		result = json_encode(root_node);
	}
	json_delete(root_node);
	return result;
}

/*
 * Module implementation.
 */

const knot_layer_api_t *hints_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = {
		.begin = &begin,
		.produce = &query,
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

int hints_init(struct kr_module *module)
{
	module->data = NULL;
	return 0;
}

int hints_config(struct kr_module *module, const char *conf)
{
	unload(module);
	if (!conf || strlen(conf) < 1) {
		conf = DEFAULT_FILE;
	}
	return load(module, conf);
}

int hints_deinit(struct kr_module *module)
{
	unload(module);
	return kr_ok();
}

struct kr_prop *hints_props(void)
{
	static struct kr_prop prop_list[] = {
	    { &hint_set,    "set", "Set {name, address} hint.", },
	    { &hint_get,    "get", "Retrieve hint for given name.", },
	    { &hint_root,   "root", "Replace root hints set (empty value to return current list).", },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(hints);
