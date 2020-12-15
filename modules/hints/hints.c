/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file hints.c
 * @brief Constructed zone cut from the hosts-like file, see @zonecut.h
 *
 * The module provides an override for queried address records.
 */

#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <ccan/json/json.h>
#include <ucw/mempool.h>
#include <contrib/cleanup.h>
#include <lauxlib.h>

#include "daemon/engine.h"
#include "lib/zonecut.h"
#include "lib/module.h"
#include "lib/layer.h"

#include <inttypes.h>
#include <math.h>

/* Defaults */
#define VERBOSE_MSG(qry, ...) QRVERBOSE(qry, "hint",  __VA_ARGS__)
#define ERR_MSG(...) kr_log_error("[     ][hint] " __VA_ARGS__)

struct hints_data {
	struct kr_zonecut hints;
	struct kr_zonecut reverse_hints;
	bool use_nodata; /**< See hint_use_nodata() description, exposed via lua. */
	uint32_t ttl;    /**< TTL used for the hints, exposed via lua. */
};
static const uint32_t HINTS_TTL_DEFAULT = 5;

/** Useful for returning from module properties. */
static char * bool2jsonstr(bool val)
{
	char *result = NULL;
	if (-1 == asprintf(&result, "{ \"result\": %s }", val ? "true" : "false"))
		result = NULL;
	return result;
}

static int put_answer(knot_pkt_t *pkt, struct kr_query *qry, knot_rrset_t *rr, bool use_nodata)
{
	int ret = 0;
	if (!knot_rrset_empty(rr) || use_nodata) {
		/* Update packet question */
		if (!knot_dname_is_equal(knot_pkt_qname(pkt), rr->owner)) {
			kr_pkt_recycle(pkt);
			knot_pkt_put_question(pkt, qry->sname, qry->sclass, qry->stype);
		}
		if (!knot_rrset_empty(rr)) {
			/* Append to packet */
			ret = knot_pkt_put_rotate(pkt, KNOT_COMPR_HINT_QNAME, rr,
						  qry->reorder, KNOT_PF_FREE);
		} else {
			/* Return empty answer if name exists, but type doesn't match */
			knot_wire_set_aa(pkt->wire);
		}
	} else {
		ret = kr_error(ENOENT);
	}
	/* Clear RR if failed */
	if (ret != 0) {
		knot_rrset_clear(rr, &pkt->mm);
	}
	return ret;
}

static int satisfy_reverse(/*const*/ struct hints_data *data,
			   knot_pkt_t *pkt, struct kr_query *qry)
{
	/* Find a matching name */
	pack_t *addr_set = kr_zonecut_find(&data->reverse_hints, qry->sname);
	if (!addr_set || addr_set->len == 0) {
		return kr_error(ENOENT);
	}
	knot_dname_t *qname = knot_dname_copy(qry->sname, &pkt->mm);
	knot_rrset_t rr;
	knot_rrset_init(&rr, qname, KNOT_RRTYPE_PTR, KNOT_CLASS_IN, data->ttl);

	/* Append address records from hints */
	uint8_t *addr = pack_last(*addr_set);
	if (addr != NULL) {
		size_t len = pack_obj_len(addr);
		void *addr_val = pack_obj_val(addr);
		knot_rrset_add_rdata(&rr, addr_val, len, &pkt->mm);
	}

	return put_answer(pkt, qry, &rr, data->use_nodata);
}

static int satisfy_forward(/*const*/ struct hints_data *data,
			   knot_pkt_t *pkt, struct kr_query *qry)
{
	/* Find a matching name */
	pack_t *addr_set = kr_zonecut_find(&data->hints, qry->sname);
	if (!addr_set || addr_set->len == 0) {
		return kr_error(ENOENT);
	}
	knot_dname_t *qname = knot_dname_copy(qry->sname, &pkt->mm);
	knot_rrset_t rr;
	knot_rrset_init(&rr, qname, qry->stype, qry->sclass, data->ttl);

	size_t family_len;
	switch (rr.type) {
	case KNOT_RRTYPE_A:
		family_len = sizeof(struct in_addr);
		break;
	case KNOT_RRTYPE_AAAA:
		family_len = sizeof(struct in6_addr);
		break;
	default:
		goto finish;
	};

	/* Append address records from hints */
	uint8_t *addr = pack_head(*addr_set);
	while (addr != pack_tail(*addr_set)) {
		size_t len = pack_obj_len(addr);
		void *addr_val = pack_obj_val(addr);
		if (len == family_len) {
			knot_rrset_add_rdata(&rr, addr_val, len, &pkt->mm);
		}
		addr = pack_obj_next(addr);
	}
finish:
	return put_answer(pkt, qry, &rr, data->use_nodata);
}

static int query(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_query *qry = ctx->req->current_query;
	if (!qry || (ctx->state & KR_STATE_FAIL)) {
		return ctx->state;
	}

	struct kr_module *module = ctx->api->data;
	struct hints_data *data = module->data;
	if (!data) { /* No valid file. */
		return ctx->state;
	}
	/* We can optimize for early return like this: */
	if (!data->use_nodata && qry->stype != KNOT_RRTYPE_A
	    && qry->stype != KNOT_RRTYPE_AAAA && qry->stype != KNOT_RRTYPE_PTR) {
		return ctx->state;
	}
	/* FIXME: putting directly into packet breaks ordering in case the hint
	 * is applied after a CNAME jump. */
	if (knot_dname_in_bailiwick(qry->sname, (const uint8_t *)"\4arpa\0") >= 0) {
		if (satisfy_reverse(data, pkt, qry) != 0)
			return ctx->state;
	} else {
		if (satisfy_forward(data, pkt, qry) != 0)
			return ctx->state;
	}

	VERBOSE_MSG(qry, "<= answered from hints\n");
	qry->flags.DNSSEC_WANT = false; /* Never authenticated */
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	pkt->parsed = pkt->size;
	knot_wire_set_qr(pkt->wire);
	return KR_STATE_DONE;
}

static int parse_addr_str(union inaddr *sa, const char *addr)
{
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	memset(sa, 0, sizeof(*sa));
	sa->ip.sa_family = family;
	char *addr_bytes = (/*const*/char *)kr_inaddr(&sa->ip);
	if (inet_pton(family, addr, addr_bytes) != 1) {
		return kr_error(EILSEQ);
	}
	return 0;
}

/** @warning _NOT_ thread-safe; returns a pointer to static data! */
static const knot_dname_t * raw_addr2reverse(const uint8_t *raw_addr, int family)
{
	#define REV_MAXLEN (4*16 + 16 /* the suffix, terminator, etc. */)
	char reverse_addr[REV_MAXLEN];
	static knot_dname_t dname[REV_MAXLEN];
	#undef REV_MAXLEN

	if (family == AF_INET) {
		snprintf(reverse_addr, sizeof(reverse_addr),
			 "%d.%d.%d.%d.in-addr.arpa.",
		         raw_addr[3], raw_addr[2], raw_addr[1], raw_addr[0]);
	} else if (family == AF_INET6) {
		char *ra_it = reverse_addr;
		for (int i = 15; i >= 0; --i) {
			ssize_t free_space = reverse_addr + sizeof(reverse_addr) - ra_it;
			int written = snprintf(ra_it, free_space, "%x.%x.",
						raw_addr[i] & 0x0f, raw_addr[i] >> 4);
			if (written >= free_space) {
				assert(false);
				return NULL;
			}
			ra_it += written;
		}
		ssize_t free_space = reverse_addr + sizeof(reverse_addr) - ra_it;
		if (snprintf(ra_it, free_space, "ip6.arpa.") >= free_space) {
			return NULL;
		}
	} else {
		return NULL;
	}
	
	if (!knot_dname_from_str(dname, reverse_addr, sizeof(dname))) {
		return NULL;
	}
	return dname;
}

static const knot_dname_t * addr2reverse(const char *addr)
{
	/* Parse address string */
	union inaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return NULL;
	}
	return raw_addr2reverse((const /*sign*/uint8_t *)kr_inaddr(&ia.ip),
				kr_inaddr_family(&ia.ip));
}

static int add_pair(struct kr_zonecut *hints, const char *name, const char *addr)
{
	/* Build key */
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(key, name, sizeof(key))) {
		return kr_error(EINVAL);
	}
	knot_dname_to_lower(key);

	union inaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return kr_error(EINVAL);
	}

	return kr_zonecut_add(hints, key, kr_inaddr(&ia.ip), kr_inaddr_len(&ia.ip));
}

static int add_reverse_pair(struct kr_zonecut *hints, const char *name, const char *addr)
{
	const knot_dname_t *key = addr2reverse(addr);

	if (key == NULL) {
		return kr_error(EINVAL);
	}

	knot_dname_t ptr_name[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(ptr_name, name, sizeof(ptr_name))) {
		return kr_error(EINVAL);
	}

	return kr_zonecut_add(hints, key, ptr_name, knot_dname_size(ptr_name));
}

/** For a given name, remove either one address or all of them (if == NULL).
 *
 * Also remove the corresponding reverse records.
 */
static int del_pair(struct hints_data *data, const char *name, const char *addr)
{
	/* Build key */
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(key, name, sizeof(key))) {
		return kr_error(EINVAL);
	}
	int key_len = knot_dname_size(key);

        if (addr) {
		/* Remove the pair. */
		union inaddr ia;
		if (parse_addr_str(&ia, addr) != 0) {
			return kr_error(EINVAL);
		}

		const knot_dname_t *reverse_key = addr2reverse(addr);
		kr_zonecut_del(&data->reverse_hints, reverse_key, key, key_len);
		return kr_zonecut_del(&data->hints, key,
					kr_inaddr(&ia.ip), kr_inaddr_len(&ia.ip));
	}
	/* We're removing everything for the name;
	 * first find the name's pack */
	pack_t *addr_set = kr_zonecut_find(&data->hints, key);
	if (!addr_set || addr_set->len == 0) {
		return kr_error(ENOENT);
	}

	/* Remove address records in hints from reverse_hints. */

	for (uint8_t *a = pack_head(*addr_set); a != pack_tail(*addr_set);
						a = pack_obj_next(a)) {
		void *addr_val = pack_obj_val(a);
		int family = pack_obj_len(a) == kr_family_len(AF_INET)
				? AF_INET : AF_INET6;
		const knot_dname_t *reverse_key = raw_addr2reverse(addr_val, family);
		if (reverse_key != NULL) {
			kr_zonecut_del(&data->reverse_hints, reverse_key, key, key_len);
		}
	}

	/* Remove the whole name. */
	return kr_zonecut_del_all(&data->hints, key);
}

static int load_file(struct kr_module *module, const char *path)
{
	auto_fclose FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		ERR_MSG("reading '%s' failed: %s\n", path, strerror(errno));
		return kr_error(errno);
	} else {
		VERBOSE_MSG(NULL, "reading '%s'\n", path);
	}

	/* Load file to map */
	struct hints_data *data = module->data;
	size_t line_len = 0;
	size_t count = 0;
	size_t line_count = 0;
	auto_free char *line = NULL;
	int ret = kr_ok();

	while (getline(&line, &line_len, fp) > 0) {
		++line_count;
		char *saveptr = NULL;
		const char *addr = strtok_r(line, " \t\n", &saveptr);
		if (addr == NULL || strchr(addr, '#') || strlen(addr) == 0) {
			continue;
		}
		const char *canonical_name = strtok_r(NULL, " \t\n", &saveptr);
		if (canonical_name == NULL) {
			ret = -1;
			goto error;
		}
		/* Since the last added PTR records takes preference,
		 * we add canonical name as the last one. */
		const char *name_tok;
		while ((name_tok = strtok_r(NULL, " \t\n", &saveptr)) != NULL) {
			ret = add_pair(&data->hints, name_tok, addr);
			if (!ret) {
				ret = add_reverse_pair(&data->reverse_hints, name_tok, addr);
			}
			if (ret) {
				ret = -1;
				goto error;
			}
			count += 1;
		}
		ret = add_pair(&data->hints, canonical_name, addr);
		if (!ret) {
			ret = add_reverse_pair(&data->reverse_hints, canonical_name, addr);
		}
		if (ret) {
			ret = -1;
			goto error;
		}
		count += 1;
	}
error:
	if (ret) {
		ret = kr_error(ret);
		ERR_MSG("%s:%zu: invalid syntax\n", path, line_count);
	}
	VERBOSE_MSG(NULL, "loaded %zu hints\n", count);
	return ret;
}

static char* hint_add_hosts(void *env, struct kr_module *module, const char *args)
{
	if (!args)
		args = "/etc/hosts";
	int err = load_file(module, args);
	return bool2jsonstr(err == kr_ok());
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
	struct hints_data *data = module->data;
	if (!args)
		return NULL;
	auto_free char *args_copy = strdup(args);
	if (!args_copy)
		return NULL;

	int ret = -1;
	char *addr = strchr(args_copy, ' ');
	if (addr) {
		*addr = '\0';
		++addr;
		ret = add_reverse_pair(&data->reverse_hints, args_copy, addr);
		if (ret) {
			del_pair(data, args_copy, addr);
		} else {
			ret = add_pair(&data->hints, args_copy, addr);
		}
	}

	return bool2jsonstr(ret == 0);
}

static char* hint_del(void *env, struct kr_module *module, const char *args)
{
	struct hints_data *data = module->data;
	if (!args)
		return NULL;
	auto_free char *args_copy = strdup(args);
	if (!args_copy)
		return NULL;

	int ret = -1;
	char *addr = strchr(args_copy, ' ');
	if (addr) {
		*addr = '\0';
		++addr;
	}
	ret = del_pair(data, args_copy, addr);

	return bool2jsonstr(ret == 0);
}

/** @internal Pack address list into JSON array. */
static JsonNode *pack_addrs(pack_t *pack)
{
	char buf[INET6_ADDRSTRLEN];
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

static char* pack_hints(struct kr_zonecut *hints);
/**
 * Retrieve address hints, either for given name or for all names.
 *
 * Input:  name
 * Output: NULL or "{ address1, address2, ... }"
 */
static char* hint_get(void *env, struct kr_module *module, const char *args)
{
	struct kr_zonecut *hints = &((struct hints_data *) module->data)->hints;
	if (!hints) {
		assert(false);
		return NULL;
	}

	if (!args) {
		return pack_hints(hints);
	}

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

/** @internal Pack all hints into serialized JSON. */
static char* pack_hints(struct kr_zonecut *hints) {
	char *result = NULL;
	JsonNode *root_node = json_mkobject();
	trie_it_t *it;
	for (it = trie_it_begin(hints->nsset); !trie_it_finished(it); trie_it_next(it)) {
		KR_DNAME_GET_STR(nsname_str, (const knot_dname_t *)trie_it_key(it, NULL));
		JsonNode *addr_list = pack_addrs((pack_t *)*trie_it_val(it));
		if (!addr_list) goto error;
		json_append_member(root_node, nsname_str, addr_list);
	}
	result = json_encode(root_node);
error:
	trie_it_free(it);
	json_delete(root_node);
	return result;
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
	if (args && args[0] != '\0') {
		JsonNode *root_node = json_decode(args);
		kr_zonecut_set(root_hints, (const uint8_t *)"");
		unpack_hint(root_hints, root_node, NULL);
		json_delete(root_node);
	}
	/* Return current root hints */
	return pack_hints(root_hints);
}

static char* hint_root_file(void *env, struct kr_module *module, const char *args)
{
	struct engine *engine = env;
	struct kr_context *ctx = &engine->resolver;
	const char *err_msg = engine_hint_root_file(ctx, args);
	if (err_msg) {
		luaL_error(engine->L, "error when opening '%s': %s", args, err_msg);
	}
	return strdup(err_msg ? err_msg : "");
}

static char* hint_use_nodata(void *env, struct kr_module *module, const char *args)
{
	struct hints_data *data = module->data;
	if (!args) {
		return NULL;
	}

	JsonNode *root_node = json_decode(args);
	if (!root_node || root_node->tag != JSON_BOOL) {
		json_delete(root_node);
		return bool2jsonstr(false);
	}

	data->use_nodata = root_node->bool_;
	json_delete(root_node);
	return bool2jsonstr(true);
}

static char* hint_ttl(void *env, struct kr_module *module, const char *args)
{
	struct hints_data *data = module->data;

	/* Do no change on nonsense TTL values (incl. suspicious floats). */
	JsonNode *root_node = args ? json_decode(args) : NULL;
	if (root_node && root_node->tag == JSON_NUMBER) {
		double ttl_d = root_node->number_;
		uint32_t ttl = (uint32_t)round(ttl_d);
		if (ttl_d >= 0 && fabs(ttl_d - ttl) * 64 < 1) {
			data->ttl = ttl;
		}
	}
	json_delete(root_node);

	/* Always return the current TTL setting.  Plain number is valid JSON. */
	char *result = NULL;
	if (-1 == asprintf(&result, "%"PRIu32, data->ttl)) {
		result = NULL;
	}
	return result;
}

/** Basic initialization: get a memory pool, etc. */
KR_EXPORT
int hints_init(struct kr_module *module)
{
	static kr_layer_api_t layer = {
		.produce = &query,
	};
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	    { &hint_set,    "set", "Set {name, address} hint.", },
	    { &hint_del,    "del", "Delete one {name, address} hint or all addresses for the name.", },
	    { &hint_get,    "get", "Retrieve hint for given name.", },
	    { &hint_ttl,    "ttl", "Set/get TTL used for the hints.", },
	    { &hint_add_hosts, "add_hosts", "Load a file with hosts-like formatting and add contents into hints.", },
	    { &hint_root,   "root", "Replace root hints set (empty value to return current list).", },
	    { &hint_root_file, "root_file", "Replace root hints set from a zonefile.", },
	    { &hint_use_nodata, "use_nodata", "Synthesise NODATA if name matches, but type doesn't.  True by default.", },
	    { NULL, NULL, NULL }
	};
	module->props = props;

	/* Create pool and copy itself */
	knot_mm_t _pool = {
		.ctx = mp_new(4096),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};
	knot_mm_t *pool = mm_alloc(&_pool, sizeof(*pool));
	if (!pool) {
		return kr_error(ENOMEM);
	}
	memcpy(pool, &_pool, sizeof(*pool));

	struct hints_data *data = mm_alloc(pool, sizeof(struct hints_data));
	if (!data) {
		mp_delete(pool->ctx);
		return kr_error(ENOMEM);
	}
	kr_zonecut_init(&data->hints, (const uint8_t *)(""), pool);
	kr_zonecut_init(&data->reverse_hints, (const uint8_t *)(""), pool);
	data->use_nodata = true;
	data->ttl = HINTS_TTL_DEFAULT;
	module->data = data;

	return kr_ok();
}

/** Release all resources. */
KR_EXPORT
int hints_deinit(struct kr_module *module)
{
	struct hints_data *data = module->data;
	if (data) {
		kr_zonecut_deinit(&data->hints);
		kr_zonecut_deinit(&data->reverse_hints);
		mp_delete(data->hints.pool->ctx);
		module->data = NULL;
	}
	return kr_ok();
}

/** Drop all hints, and load a hosts file if any was specified.
 *
 * It seems slightly strange to drop all, but keep doing that for now.
 */
KR_EXPORT
int hints_config(struct kr_module *module, const char *conf)
{
	hints_deinit(module);
	int err = hints_init(module);
	if (err != kr_ok()) {
		return err;
	}

	if (conf && conf[0]) {
		return load_file(module, conf);
	}
	return kr_ok();
}

KR_MODULE_EXPORT(hints)

#undef VERBOSE_MSG
