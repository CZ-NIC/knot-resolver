#include <libknot/descriptor.h>

#include "lib/rplan.h"

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

void kr_rplan_init(struct kr_rplan *rplan, mm_ctx_t *pool)
{
	rplan->pool = pool;
	init_list(&rplan->q);
}

void kr_rplan_clear(struct kr_rplan *rplan)
{
	struct kr_query *qry = NULL, *next = NULL;
	WALK_LIST_DELSAFE(qry, next, rplan->q) {
		query_free(rplan->pool, qry);
	}

	kr_rplan_init(rplan, rplan->pool);
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
	qry->flags = RESOLVE_QUERY;

	add_head(&rplan->q, &qry->node);
	return qry;
}

int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry)
{
	rem_node(&qry->node);
	query_free(rplan->pool, qry);
	return 0;
}

struct kr_query *kr_rplan_next(struct kr_rplan *rplan)
{
	if (EMPTY_LIST(rplan->q)) {
		return NULL;
	}
	return HEAD(rplan->q);
}
