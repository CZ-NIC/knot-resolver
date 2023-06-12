/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
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
#include "lib/rules/api.h"

#include <inttypes.h>
#include <math.h>

/* Defaults */
#define VERBOSE_MSG(qry, ...) kr_log_q(qry, HINT,  __VA_ARGS__)
#define ERR_MSG(...) kr_log_error(HINT, "[     ]" __VA_ARGS__)

struct hints_data {
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

static int parse_addr_str(union kr_sockaddr *sa, const char *addr)
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
			if (kr_fails_assert(written < free_space))
				return NULL;
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
	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return NULL;
	}
	return raw_addr2reverse((const /*sign*/uint8_t *)kr_inaddr(&ia.ip),
				kr_inaddr_family(&ia.ip));
}

static int add_pair_root(struct kr_zonecut *hints, const char *name, const char *addr)
{
	/* Build key */
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(key, name, sizeof(key))) {
		return kr_error(EINVAL);
	}
	knot_dname_to_lower(key);

	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return kr_error(EINVAL);
	}
	return kr_zonecut_add(hints, key, kr_inaddr(&ia.ip), kr_inaddr_len(&ia.ip));
}

static int add_pair(const struct hints_data *data, const char *name, const char *addr)
{
	/* Build key */
	knot_dname_t key[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(key, name, sizeof(key))) {
		return kr_error(EINVAL);
	}
	knot_dname_to_lower(key);

	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0) {
		return kr_error(EINVAL);
	}

	uint16_t rrtype = ia.ip.sa_family == AF_INET6 ? KNOT_RRTYPE_AAAA : KNOT_RRTYPE_A;
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, key, rrtype, KNOT_CLASS_IN, data->ttl);
	int ret;
	if (ia.ip.sa_family == AF_INET6) {
		ret = knot_rrset_add_rdata(&rrs, (const uint8_t *)&ia.ip6.sin6_addr, 16, NULL);
	} else {
		ret = knot_rrset_add_rdata(&rrs, (const uint8_t *)&ia.ip4.sin_addr, 4, NULL);
	}
	if (!ret) ret = kr_rule_local_data_ins(&rrs, NULL, KR_RULE_TAGS_ALL);
	if (!ret && data->use_nodata) {
		rrs.type = KNOT_RRTYPE_CNAME;
		rrs.rrs.count = 0;
		rrs.rrs.size = 0;
		ret = kr_rule_local_data_ins(&rrs, NULL, KR_RULE_TAGS_ALL);
	}

	knot_rdataset_clear(&rrs.rrs, NULL);
	return ret;
}

static int add_reverse_pair(const struct hints_data *data, const char *name, const char *addr)
{
	const knot_dname_t *key = addr2reverse(addr);
	if (!key)
		return kr_error(EINVAL);
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, /*const-cast*/(knot_dname_t *)key,
			KNOT_RRTYPE_PTR, KNOT_CLASS_IN, data->ttl);
	knot_dname_t ptr_name[KNOT_DNAME_MAXLEN];
	if (!knot_dname_from_str(ptr_name, name, sizeof(ptr_name)))
		return kr_error(EINVAL);
	int ret = knot_rrset_add_rdata(&rrs, ptr_name, knot_dname_size(ptr_name), NULL);
	if (!ret) {
		ret = kr_rule_local_data_ins(&rrs, NULL, KR_RULE_TAGS_ALL);
		knot_rdataset_clear(&rrs.rrs, NULL);
	}
	return ret;
}

/** For a given name, remove either one address  ##or all of them (if == NULL).
 *
 * Also remove the corresponding reverse records.
 */
static int del_pair(struct hints_data *data, const char *name, const char *addr)
{
	// Parse addr
	if (!addr)
		return kr_error(ENOSYS);
	union kr_sockaddr ia;
	if (parse_addr_str(&ia, addr) != 0)
		return kr_error(EINVAL);

	// Remove the PTR
	const knot_dname_t *reverse_key = addr2reverse(addr);
	knot_rrset_t rrs;
	knot_rrset_init(&rrs, /*const-cast*/(knot_dname_t *)reverse_key,
			KNOT_RRTYPE_PTR, KNOT_CLASS_IN, data->ttl);
	int ret = kr_rule_local_data_del(&rrs, KR_RULE_TAGS_ALL);
	if (ret != 1)
		VERBOSE_MSG(NULL, "del_pair PTR for %s; error: %s\n", addr, kr_strerror(ret));
	if (ret != 1 && ret != kr_error(ENOENT)) // ignore ENOENT for PTR (duplicities)
		return ret;

	// Remove the forward entry
	knot_dname_t key_buf[KNOT_DNAME_MAXLEN];
	rrs.owner = knot_dname_from_str(key_buf, name, sizeof(key_buf));
	if (!rrs.owner)
		return kr_error(EINVAL);
	rrs.type = ia.ip.sa_family == AF_INET6 ? KNOT_RRTYPE_AAAA : KNOT_RRTYPE_A;
	ret = kr_rule_local_data_del(&rrs, KR_RULE_TAGS_ALL);
	if (ret != 1)
		VERBOSE_MSG(NULL, "del_pair for %s; error: %s\n", name, kr_strerror(ret));

	// Remove the NODATA entry; again, not perfect matching,
	//  but we don't care much about this dynamic hints API.
	if (ret == 1 && data->use_nodata) {
		rrs.type = KNOT_RRTYPE_CNAME;
		ret = kr_rule_local_data_del(&rrs, KR_RULE_TAGS_ALL);
		if (ret != 1)
			VERBOSE_MSG(NULL, "del_pair for NODATA %s; error: %s\n",
					name, kr_strerror(ret));
	}
	return ret < 0 ? ret : kr_ok();
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
	size_t line_len_unused = 0;
	size_t count = 0;
	size_t line_count = 0;
	auto_free char *line = NULL;
	int ret = kr_ok();

	while (getline(&line, &line_len_unused, fp) > 0) {
		++line_count;
		/* Ingore #comments as described in man hosts.5 */
		char *comm = strchr(line, '#');
		if (comm) {
			*comm = '\0';
		}

		char *saveptr = NULL;
		const char *addr = strtok_r(line, " \t\n", &saveptr);
		if (addr == NULL || strlen(addr) == 0) {
			continue;
		}
		const char *canonical_name = strtok_r(NULL, " \t\n", &saveptr);
		if (canonical_name == NULL) {
			ret = kr_error(EINVAL);
			goto error;
		}
		const char *name_tok;
		while ((name_tok = strtok_r(NULL, " \t\n", &saveptr)) != NULL) {
			ret = add_pair(data, name_tok, addr);
			if (ret)
				goto error;
			count += 1;
		}
		ret = add_pair(data, canonical_name, addr);
		if (!ret) // PTR only to the canonical name
			ret = add_reverse_pair(data, canonical_name, addr);
		if (ret)
			goto error;
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
		ret = add_reverse_pair(data, args_copy, addr);
		if (!ret)
			ret = add_pair(data, args_copy, addr);
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
	if (ret)
		VERBOSE_MSG(NULL, "hints.del(%s) error: %s\n", args, kr_strerror(ret));

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

/**
 * Retrieve address hints, either for given name or for all names.
 *
 * Input:  name
 * Output: NULL or "{ address1, address2, ... }"
 */
static char* hint_get(void *env, struct kr_module *module, const char *args)
{
	return NULL;
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
		case JSON_STRING:
			add_pair_root(root_hints, name ? name : node->key, node->string_);
			break;
		case JSON_ARRAY:
			unpack_hint(root_hints, node, name ? name : node->key);
			break;
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
	static kr_layer_api_t layer = { 0 };
	/* Store module reference */
	layer.data = module;
	module->layer = &layer;

	static const struct kr_prop props[] = {
	/* FIXME(decide): .set() and .del() used to work on individual RRs;
	 * now they overwrite or delete whole RRsets.
	 * Also, .get() doesn't work at all.
	 *
	 * It really depends what kind of config/API we'll be exposing to user.
	 *  - Manipulating whole RRsets generally makes more sense to me.
	 *    (But hints.set() currently can't even insert larger sets.)
	 *  - We'll probably be deprecating access through these non-declarative
	 *    commands (set, get, del) which are also usable dynamically.
	 */
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

	struct hints_data *data = malloc(sizeof(*data));
	if (!data)
		return kr_error(ENOMEM);
	data->use_nodata = true;
	data->ttl = HINTS_TTL_DEFAULT;
	module->data = data;

	return kr_ok();
}

/** Release all resources. */
KR_EXPORT
int hints_deinit(struct kr_module *module)
{
	free(module->data);
	module->data = NULL;
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
