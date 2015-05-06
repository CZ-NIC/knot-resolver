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
#include <libknot/internal/lists.h>
#include <libknot/internal/mempool.h>
#include <libknot/rrtype/aaaa.h>

#include "lib/layer/iterate.h"
#include "lib/zonecut.h"
#include "lib/module.h"
#include "lib/layer.h"

/* Defaults */
#define DEFAULT_FILE "/etc/hosts"
#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "hint",  fmt)

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int answer_query(knot_pkt_t *pkt, pack_t *addr_set, struct kr_request *param)
{
	knot_dname_t *qname = knot_dname_copy(knot_pkt_qname(pkt), &pkt->mm);
	uint16_t rrtype = knot_pkt_qtype(pkt);
	uint16_t rrclass = knot_pkt_qclass(pkt);
	knot_rrset_t rr;
	knot_rrset_init(&rr, qname, rrtype, rrclass);
	int family_len = sizeof(struct in_addr);
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

	/* Append to packet */
	int ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &rr, KNOT_PF_FREE);
	if (ret != 0) {
		knot_rrset_clear(&rr, &pkt->mm);
	}
	return ret;
}

static int query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *param = ctx->data;
	struct kr_query *qry = kr_rplan_current(&param->rplan);
	if (!qry || ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}
	if (qry->stype != KNOT_RRTYPE_A && qry->stype != KNOT_RRTYPE_AAAA) {
		return ctx->state;
	}

	/* Find a matching name */
	struct kr_module *module = ctx->api->data;
	struct kr_zonecut *hint_map = module->data;
	pack_t *pack = kr_zonecut_find(hint_map, qry->sname);
	if (!pack || pack->len == 0) {
		return ctx->state;
	}

	/* Write to packet */
	int ret = answer_query(pkt, pack, param);
	if (ret != 0) {
		return ctx->state;
	}
	DEBUG_MSG(qry, "<= answered from hints\n");
	qry->flags |= QUERY_CACHED;	
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
	mm_ctx_t _pool;
	mm_ctx_mempool(&_pool, MM_DEFAULT_BLKSIZE);
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
	asprintf(&result, "{ \"result\": %s }", ret == 0 ? "true" : "false");
	return result;
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
	size_t bufsize = 4096;
	if (knot_dname_from_str(key, args, sizeof(key))) {
		pack = kr_zonecut_find(hints, key);
	}
	if (!pack || pack->len == 0) {
		return NULL;
	}

	auto_free char *hint_buf = malloc(bufsize);
	if (hint_buf == NULL) {
		return NULL;
	}
	char *p = hint_buf, *endp = hint_buf + bufsize;
	uint8_t *addr = pack_head(*pack);
	while (addr != pack_tail(*pack)) {
		size_t len = pack_obj_len(addr);
		int family = len == sizeof(struct in_addr) ? AF_INET : AF_INET6;
		if (!inet_ntop(family, pack_obj_val(addr), p, endp - p)) {
			break;
		}
		p += strlen(p);
		addr = pack_obj_next(addr);
		if (p + 2 < endp && addr != pack_tail(*pack)) {
			strcpy(p, " ");
			p += 1;
		}
	}

	char *result = NULL;
	asprintf(&result, "{ \"result\": [ %s ] }", hint_buf);
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
	return load(module, DEFAULT_FILE);
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
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(hints);
