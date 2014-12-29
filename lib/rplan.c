#include <sys/time.h>

#include <libknot/descriptor.h>
#include <libknot/processing/layer.h>
#include <libknot/errcode.h>

#include "lib/rplan.h"
#include "lib/context.h"
#include "lib/cache.h"

#define DEBUG_MSG(fmt, ...) fprintf(stderr, "[rplan] " fmt, ## __VA_ARGS__)

static struct kr_query *query_create(mm_ctx_t *pool, const knot_dname_t *name)
{
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
	mm_free(pool, qry->sname);
	mm_free(pool, qry);
}

void kr_rplan_init(struct kr_rplan *rplan, struct kr_context *context, mm_ctx_t *pool)
{
	memset(rplan, 0, sizeof(struct kr_rplan));

	rplan->state = KNOT_NS_PROC_MORE;
	rplan->pool = pool;
	rplan->context = context;
	init_list(&rplan->pending);
	init_list(&rplan->resolved);
}

void kr_rplan_deinit(struct kr_rplan *rplan)
{
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

	kr_rplan_init(rplan, rplan->context, rplan->pool);
}

bool kr_rplan_empty(struct kr_rplan *rplan)
{
	return EMPTY_LIST(rplan->pending);
}

struct kr_query *kr_rplan_push(struct kr_rplan *rplan, const knot_dname_t *name,
                               uint16_t cls, uint16_t type)
{
	struct kr_query *qry =  query_create(rplan->pool, name);
	if (qry == NULL) {
		return NULL;
	}

	qry->sclass = cls;
	qry->stype = type;
	gettimeofday(&qry->timestamp, NULL);

	add_tail(&rplan->pending, &qry->node);

#ifndef NDEBUG
	char name_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(name_str, name, sizeof(name_str));
	knot_rrtype_to_string(type, type_str, sizeof(type_str));
	DEBUG_MSG("plan '%s' type '%s'\n", name_str, type_str);
#endif

	return qry;
}

int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry)
{
	rem_node(&qry->node);
	add_tail(&rplan->resolved, &qry->node);
	return KNOT_EOK;
}

struct kr_query *kr_rplan_current(struct kr_rplan *rplan)
{
	if (EMPTY_LIST(rplan->pending)) {
		return NULL;
	}
	return TAIL(rplan->pending);
}

struct kr_query *kr_rplan_last(struct kr_rplan *rplan)
{
	if (EMPTY_LIST(rplan->pending)) {
		return NULL;
	}
	return HEAD(rplan->pending);
}

namedb_txn_t *kr_rplan_txn_acquire(struct kr_rplan *rplan, unsigned flags)
{
	if (rplan == NULL) {
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
	if (rplan == NULL) {
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

