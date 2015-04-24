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

#include <libknot/descriptor.h>
#include <libknot/processing/layer.h>
#include <libknot/errcode.h>

#include "lib/rplan.h"
#include "lib/resolve.h"
#include "lib/cache.h"
#include "lib/defines.h"
#include "lib/layer.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "plan",  fmt)
#define QUERY_PROVIDES(q, name, cls, type) \
    ((q)->sclass == (cls) && (q)->stype == type && knot_dname_is_equal((q)->sname, name))

static struct kr_query *query_create(mm_ctx_t *pool, const knot_dname_t *name)
{
	if (name == NULL) {
		return NULL;
	}

	struct kr_query *qry = mm_alloc(pool, sizeof(struct kr_query));
	if (qry == NULL) {
		return NULL;
	}

	memset(qry, 0, sizeof(struct kr_query));
	qry->sname = knot_dname_copy(name, pool);
	if (qry->sname == NULL) {
		mm_free(pool, qry);
		return NULL;
	}

	return qry;
}

static void query_free(mm_ctx_t *pool, struct kr_query *qry)
{
	kr_zonecut_deinit(&qry->zone_cut);
	mm_free(pool, qry->sname);
	mm_free(pool, qry);
}

int kr_rplan_init(struct kr_rplan *rplan, struct kr_context *context, mm_ctx_t *pool)
{
	if (rplan == NULL) {
		return KNOT_EINVAL;
	}

	memset(rplan, 0, sizeof(struct kr_rplan));

	rplan->pool = pool;
	rplan->context = context;
	init_list(&rplan->pending);
	init_list(&rplan->resolved);
	return KNOT_EOK;
}

void kr_rplan_deinit(struct kr_rplan *rplan)
{
	if (rplan == NULL) {
		return;
	}

	struct kr_query *qry = NULL, *next = NULL;
	WALK_LIST_DELSAFE(qry, next, rplan->pending) {
		query_free(rplan->pool, qry);
	}
	WALK_LIST_DELSAFE(qry, next, rplan->resolved) {
		query_free(rplan->pool, qry);
	}

	/* Abort any pending transactions. */
	if (rplan->txn.db != NULL) {
		kr_cache_txn_abort(&rplan->txn);
	}
}

bool kr_rplan_empty(struct kr_rplan *rplan)
{
	if (rplan == NULL) {
		return true;
	}

	return EMPTY_LIST(rplan->pending);
}

struct kr_query *kr_rplan_push(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type)
{
	if (rplan == NULL || name == NULL) {
		return NULL;
	}

	struct kr_query *qry = query_create(rplan->pool, name);
	if (qry == NULL) {
		return NULL;
	}
	qry->sclass = cls;
	qry->stype = type;
	qry->flags = rplan->context->options;
	qry->parent = parent;
	gettimeofday(&qry->timestamp, NULL);
	add_tail(&rplan->pending, &qry->node);

	/* Find closest zone cut for this query. */
	namedb_txn_t *txn = kr_rplan_txn_acquire(rplan, NAMEDB_RDONLY);
	kr_zonecut_init(&qry->zone_cut, name, rplan->pool);
	kr_zonecut_find_cached(&qry->zone_cut, txn, qry->timestamp.tv_sec);

#ifndef NDEBUG
	char name_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(name_str, name, sizeof(name_str));
	knot_rrtype_to_string(type, type_str, sizeof(type_str));
	DEBUG_MSG(parent, "plan '%s' type '%s'\n", name_str, type_str);
#endif
	return qry;
}

int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry)
{
	if (rplan == NULL || qry == NULL) {
		return KNOT_EINVAL;
	}

	rem_node(&qry->node);
	add_tail(&rplan->resolved, &qry->node);
	return KNOT_EOK;
}

struct kr_query *kr_rplan_current(struct kr_rplan *rplan)
{
	if (kr_rplan_empty(rplan)) {
		return NULL;
	}

	return TAIL(rplan->pending);
}

namedb_txn_t *kr_rplan_txn_acquire(struct kr_rplan *rplan, unsigned flags)
{
	if (rplan == NULL || rplan->context == NULL) {
		return NULL;
	}

	/* Discard current transaction if RDONLY, but WR is requested. */
	if ((rplan->txn_flags & NAMEDB_RDONLY) && !(flags & NAMEDB_RDONLY)) {
		kr_cache_txn_abort(&rplan->txn);
		rplan->txn.db = NULL;
	}

	/* Reuse transaction if exists. */
	if (rplan->txn.db != NULL) {
		return &rplan->txn;
	}

	/* Transaction doesn't exist, start new one. */
	int ret = kr_cache_txn_begin(rplan->context->cache, &rplan->txn, flags);
	if (ret != KNOT_EOK) {
		rplan->txn.db = NULL;
		return NULL;
	}

	rplan->txn_flags = flags;
	return &rplan->txn;
}

int kr_rplan_txn_commit(struct kr_rplan *rplan)
{
	if (rplan == NULL || rplan->context == NULL) {
		return KNOT_EINVAL;
	}

	/* Just discard RDONLY transactions. */
	int ret = KNOT_EOK;
	if (rplan->txn_flags & NAMEDB_RDONLY) {
		kr_cache_txn_abort(&rplan->txn);
	} else {
		/* Commit write transactions. */
		ret = kr_cache_txn_commit(&rplan->txn);
	}

	rplan->txn.db = NULL;
	return ret;
}

bool kr_rplan_satisfies(struct kr_query *closure, const knot_dname_t *name, uint16_t cls, uint16_t type)
{
	while (closure != NULL) {
		if (QUERY_PROVIDES(closure, name, cls, type)) {
			return true;
		}
		closure = closure->parent;
	}
	return false;
}
