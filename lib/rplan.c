/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <libknot/descriptor.h>
#include <libknot/errcode.h>

#include "lib/rplan.h"
#include "lib/resolve.h"
#include "lib/cache/api.h"
#include "lib/defines.h"
#include "lib/layer.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "plan",  fmt)
#define QUERY_PROVIDES(q, name, cls, type) \
    ((q)->sclass == (cls) && (q)->stype == type && knot_dname_is_equal((q)->sname, name))

inline static unsigned char chars_or(const unsigned char a, const unsigned char b)
{
	return a | b;
}

/** Bits set to 1 in variable b will be set to zero in variable a. */
inline static unsigned char chars_mask(const unsigned char a, const unsigned char b)
{
	return a & ~b;
}

/** Apply mod(a, b) to every byte a, b from fl1, fl2 and return result in fl1. */
inline static void kr_qflags_mod(struct kr_qflags *fl1, struct kr_qflags fl2,
			unsigned char mod(const unsigned char a, const unsigned char b))
{
	if (!fl1) abort();
	union {
		struct kr_qflags flags;
		/* C99 section 6.5.3.4: sizeof(char) == 1 */
		unsigned char chars[sizeof(struct kr_qflags)];
	} tmp1, tmp2;
	/* The compiler should be able to optimize all this into simple ORs. */
	tmp1.flags = *fl1;
	tmp2.flags = fl2;
	for (size_t i = 0; i < sizeof(struct kr_qflags); ++i) {
		tmp1.chars[i] = mod(tmp1.chars[i], tmp2.chars[i]);
	}
	*fl1 = tmp1.flags;
}

/**
 * Set bits from variable fl2 in variable fl1.
 * Bits which are not set in fl2 are not modified in fl1.
 *
 * @param[in,out] fl1
 * @param[in] fl2
 */
void kr_qflags_set(struct kr_qflags *fl1, struct kr_qflags fl2)
{
	kr_qflags_mod(fl1, fl2, chars_or);
}

/**
 * Clear bits from variable fl2 in variable fl1.
 * Bits which are not set in fl2 are not modified in fl1.
 *
 * @param[in,out] fl1
 * @param[in] fl2
 */
void kr_qflags_clear(struct kr_qflags *fl1, struct kr_qflags fl2)
{
	kr_qflags_mod(fl1, fl2, chars_mask);
}

static struct kr_query *query_create(knot_mm_t *pool, const knot_dname_t *name, uint32_t uid)
{
	struct kr_query *qry = mm_alloc(pool, sizeof(struct kr_query));
	if (qry == NULL) {
		return NULL;
	}

	memset(qry, 0, sizeof(struct kr_query));
	if (name != NULL) {
		qry->sname = knot_dname_copy(name, pool);
		if (qry->sname == NULL) {
			mm_free(pool, qry);
			return NULL;
		}
	}

	knot_dname_to_lower(qry->sname);
	qry->uid = uid;
	return qry;
}

static void query_free(knot_mm_t *pool, struct kr_query *qry)
{
	kr_zonecut_deinit(&qry->zone_cut);
	mm_free(pool, qry->sname);
	mm_free(pool, qry);
}

int kr_rplan_init(struct kr_rplan *rplan, struct kr_request *request, knot_mm_t *pool)
{
	if (rplan == NULL) {
		return KNOT_EINVAL;
	}

	memset(rplan, 0, sizeof(struct kr_rplan));

	rplan->pool = pool;
	rplan->request = request;
	array_init(rplan->pending);
	array_init(rplan->resolved);
	rplan->next_uid = 0;
	return KNOT_EOK;
}

void kr_rplan_deinit(struct kr_rplan *rplan)
{
	if (rplan == NULL) {
		return;
	}

	for (size_t i = 0; i < rplan->pending.len; ++i) {
		query_free(rplan->pool, rplan->pending.at[i]);
	}
	for (size_t i = 0; i < rplan->resolved.len; ++i) {
		query_free(rplan->pool, rplan->resolved.at[i]);
	}
	array_clear_mm(rplan->pending, mm_free, rplan->pool);
	array_clear_mm(rplan->resolved, mm_free, rplan->pool);
}

bool kr_rplan_empty(struct kr_rplan *rplan)
{
	if (rplan == NULL) {
		return true;
	}

	return rplan->pending.len == 0;
}

static struct kr_query *kr_rplan_push_query(struct kr_rplan *rplan,
                                            struct kr_query *parent,
                                            const knot_dname_t *name)
{
	if (rplan == NULL) {
		return NULL;
	}

	/* Make sure there's enough space */
	int ret = array_reserve_mm(rplan->pending, rplan->pending.len + 1, kr_memreserve, rplan->pool);
	if (ret != 0) {
		return NULL;
	}

	struct kr_query *qry = query_create(rplan->pool, name, rplan->next_uid);
	if (qry == NULL) {
		return NULL;
	}
	rplan->next_uid += 1;
	/* Class and type must be set outside this function. */
	qry->flags = rplan->request->options;
	qry->parent = parent;
	qry->request = rplan->request;
	qry->ns.ctx = rplan->request->ctx;
	qry->ns.addr[0].ip.sa_family = AF_UNSPEC;
	gettimeofday(&qry->timestamp, NULL);
	qry->timestamp_mono = kr_now();
	qry->creation_time_mono = parent ? parent->creation_time_mono : qry->timestamp_mono;
	kr_zonecut_init(&qry->zone_cut, (const uint8_t *)"", rplan->pool);
	qry->reorder = qry->flags.REORDER_RR
		? knot_wire_get_id(rplan->request->answer->wire)
		: 0;

	/* When forwarding, keep the nameserver addresses. */
	if (parent && parent->flags.FORWARD && qry->flags.FORWARD) {
		ret = kr_nsrep_copy_set(&qry->ns, &parent->ns);
		if (ret) {
			query_free(rplan->pool, qry);
			return NULL;
		}
	}

	array_push(rplan->pending, qry);

	return qry;
}

struct kr_query *kr_rplan_push_empty(struct kr_rplan *rplan, struct kr_query *parent)
{
	if (rplan == NULL) {
		return NULL;
	}

	struct kr_query *qry = kr_rplan_push_query(rplan, parent, NULL);
	if (qry == NULL) {
		return NULL;
	}

	WITH_VERBOSE(qry) {
	VERBOSE_MSG(qry, "plan '%s' type '%s'\n", "", "");
	}
	return qry;
}

struct kr_query *kr_rplan_push(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type)
{
	if (rplan == NULL || name == NULL) {
		return NULL;
	}

	struct kr_query *qry = kr_rplan_push_query(rplan, parent, name);
	if (qry == NULL) {
		return NULL;
	}

	qry->sclass = cls;
	qry->stype = type;

	WITH_VERBOSE(qry) {
	char name_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(name_str, name, sizeof(name_str));
	knot_rrtype_to_string(type, type_str, sizeof(type_str));
	VERBOSE_MSG(parent, "plan '%s' type '%s'\n", name_str, type_str);
	}
	return qry;
}

int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry)
{
	if (rplan == NULL || qry == NULL) {
		return KNOT_EINVAL;
	}

	/* Make sure there's enough space */
	int ret = array_reserve_mm(rplan->resolved, rplan->resolved.len + 1, kr_memreserve, rplan->pool);
	if (ret != 0) {
		return ret;
	}

	/* Find the query, it will likely be on top */
	for (size_t i = rplan->pending.len; i > 0; i--) {
		if (rplan->pending.at[i - 1] == qry) {
			array_del(rplan->pending, i - 1);
			array_push(rplan->resolved, qry);
			break;
		}
	}
	return KNOT_EOK;
}

bool kr_rplan_satisfies(struct kr_query *closure, const knot_dname_t *name, uint16_t cls, uint16_t type)
{
	while (name && closure) {
		if (QUERY_PROVIDES(closure, name, cls, type)) {
			return true;
		}
		closure = closure->parent;
	}
	return false;
}

struct kr_query *kr_rplan_resolved(struct kr_rplan *rplan)
{
	if (rplan->resolved.len == 0) {
		return NULL;
	}
	return array_tail(rplan->resolved);
}

struct kr_query *kr_rplan_last(struct kr_rplan *rplan)
{
	if (!kr_rplan_empty(rplan)) {
		return array_tail(rplan->pending);
	}

	return kr_rplan_resolved(rplan);
}

struct kr_query *kr_rplan_find_resolved(struct kr_rplan *rplan, struct kr_query *parent,
                               const knot_dname_t *name, uint16_t cls, uint16_t type)
{
	struct kr_query *ret = NULL;
	for (int i = 0; i < rplan->resolved.len; ++i) {
		struct kr_query *q = rplan->resolved.at[i];
		if (q->stype == type && q->sclass == cls &&
		    (parent == NULL || q->parent == parent) &&
		    knot_dname_is_equal(q->sname, name)) {
			ret = q;
			break;
		}
	}
	return ret;
}

#undef VERBOSE_MSG
