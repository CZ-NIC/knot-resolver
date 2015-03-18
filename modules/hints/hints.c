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

#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <libknot/internal/lists.h>
#include <libknot/internal/mempool.h>
#include <libknot/rrtype/aaaa.h>

#include "lib/layer/iterate.h"
#include "lib/utils.h"
#include "lib/defines.h"
#include "lib/module.h"
#include "lib/layer.h"

#define DEFAULT_FILE "/etc/hosts"
#define DEBUG_MSG(fmt...) QRDEBUG(NULL, "hint",  fmt)

/* TODO: this is an experimental (slow) proof-of-concept,
 *       this will be rewritten with namedb API
 */ 

typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_layer_param *);

struct hint_map
{
	list_t list;
	mm_ctx_t pool;
};

struct hint_pair
{
	node_t n;
	knot_dname_t *name;
	char *addr;
};

static struct hint_map *g_map = NULL;

static int begin(knot_layer_t *ctx, void *module_param)
{
	ctx->data = module_param;
	return ctx->state;
}

static int query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_layer_param *param = ctx->data;
	struct kr_query *cur = kr_rplan_current(param->rplan);
	if (cur == NULL) {
		return ctx->state;
	}

	const knot_dname_t *qname = knot_pkt_qname(pkt);
	uint16_t qtype = knot_pkt_qtype(pkt);
	if (qtype != KNOT_RRTYPE_A && qtype != KNOT_RRTYPE_AAAA) {
		return ctx->state;
	}

	/* Check if updating parent zone cut. */
	rr_callback_t callback = &rr_update_parent;
	if (cur->parent == NULL) {
		callback = &rr_update_answer;
	}

	struct hint_pair *pair = NULL;
	WALK_LIST(pair, g_map->list) {
		if (knot_dname_is_equal(qname, pair->name)) {
			DEBUG_MSG("found hint '%s'\n", pair->addr);
			int addr_type = strchr(pair->addr, ':') ? AF_INET6 : AF_INET;
			if ((addr_type == AF_INET) != (qtype == KNOT_RRTYPE_A)) {
				continue;
			}

			knot_rrset_t rr;
			knot_rrset_init(&rr, pair->name, qtype, KNOT_CLASS_IN);
			struct sockaddr_storage addr;
			sockaddr_set(&addr, addr_type, pair->addr, 0); 
			size_t addr_len = 0;
			uint8_t *raw_addr = sockaddr_raw(&addr, &addr_len);
			knot_rrset_add_rdata(&rr, raw_addr, addr_len, 0, &param->answer->mm);
			callback(&rr, 0, param);

			cur->resolved = true;
			return KNOT_STATE_DONE;
		}
	}

	return ctx->state;
}

static int load_map(struct hint_map *map, FILE *fp)
{
	knot_dname_t name_buf[KNOT_DNAME_MAXLEN];
	size_t line_len = 0;
	auto_free char *line = NULL;
	init_list(&map->list);

	while(getline(&line, &line_len, fp) > 0) {
		char *saveptr = NULL;
		char *tok = strtok_r(line, " \t\r", &saveptr);
		if (tok == NULL || strchr(tok, '#') || strlen(tok) == 0) {
			continue;
		}
		char *name_tok = strtok_r(NULL, " \t\n", &saveptr);
		while (name_tok != NULL) {
			struct hint_pair *pair = mm_alloc(&map->pool, sizeof(struct hint_pair));
			if (pair == NULL) {
				return kr_error(ENOMEM);
			}
			pair->name = knot_dname_from_str(name_buf, name_tok, sizeof(name_buf));
			if (pair->name == NULL) {
				continue;
			}

			pair->name = knot_dname_copy(pair->name, &map->pool);
			if (pair->name == NULL) {
				return kr_error(ENOMEM);
			}
			pair->addr = mm_alloc(&map->pool, strlen(tok) + 1);
			if (pair->addr == NULL) {
				return kr_error(ENOMEM);
			}
			
			strcpy(pair->addr, tok);
			add_tail(&map->list, &pair->n);
			name_tok = strtok_r(NULL, " \t\n", &saveptr);
		}
	}

	DEBUG_MSG("loaded %zu hints\n", list_size(&map->list));

	return kr_ok();
}

/*
 * Module implementation.
 */

const knot_layer_api_t *hints_layer(void)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.produce = &query
	};
	return &_layer;
}

int hints_init(struct kr_module *module)
{
	auto_fclose FILE *fp = fopen(DEFAULT_FILE, "r");
	if (fp == NULL) {
		DEBUG_MSG("reading %s failed", DEFAULT_FILE);
		return kr_error(errno);
	}

	mm_ctx_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);
	struct hint_map *map = mm_alloc(&pool, sizeof(struct hint_map));
	map->pool = pool;
	module->data = map;

	g_map = map;

	return load_map(map, fp);
}

int hints_deinit(struct kr_module *module)
{
	struct hint_map *map = module->data;
	if (map) {
		mp_delete(map->pool.ctx);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(hints)
