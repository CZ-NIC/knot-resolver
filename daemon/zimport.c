/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* Module is intended to import resource records from file into resolver's cache.
 * File supposed to be a standard DNS zone file
 * which contains text representations of resource records.
 * For now only root zone import is supported.
 *
 * Import process consists of two stages.
 * 1) Zone file parsing.
 * 2) Import of parsed entries into the cache.
 *
 * These stages are implemented as two separate functions
 * (zi_zone_import and zi_zone_process) which runs sequentially with the
 * pause between them. This is done because resolver is a single-threaded
 * application, so it can't process user's requests during the whole import
 * process. Separation into two stages allows to reduce the
 * continuous time interval when resolver can't serve user requests.
 * Since root zone isn't large it is imported as single
 * chunk. If it would be considered as necessary, import stage can be
 * split into shorter stages.
 *
 * zi_zone_import() uses libzscanner to parse zone file.
 * Parsed records are stored to internal storage from where they are imported to
 * cache during the second stage.
 *
 * zi_zone_process() imports parsed resource records to cache.
 * It imports rrset by creating request that will never be sent to upstream.
 * After request creation resolver creates pseudo-answer which must contain
 * all necessary data for validation. Then resolver process answer as if he had
 * been received from network.
 */

#include <inttypes.h> /* PRIu64 */
#include <limits.h>
#include <stdlib.h>
#include <uv.h>
#include <ucw/mempool.h>
#include <libknot/rrset.h>
#include <libzscanner/scanner.h>

#include "lib/utils.h"
#include "lib/dnssec/ta.h"
#include "daemon/worker.h"
#include "daemon/zimport.h"
#include "lib/generic/map.h"
#include "lib/generic/array.h"

#define VERBOSE_MSG(qry, ...) QRVERBOSE(qry, "zimport", __VA_ARGS__)

/* Pause between parse and import stages, milliseconds.
 * See comment in zi_zone_import() */
#define ZONE_IMPORT_PAUSE 100

typedef array_t(knot_rrset_t *) qr_rrsetlist_t;

struct zone_import_ctx {
	struct worker_ctx *worker;
	bool started;
	knot_dname_t *origin;
	knot_rrset_t *ta;
	knot_rrset_t *key;
	uint64_t start_timestamp;
	size_t rrset_idx;
	uv_timer_t timer;
	map_t rrset_indexed;
	qr_rrsetlist_t rrset_sorted;
	knot_mm_t pool;
	zi_callback cb;
	void *cb_param;
};

typedef struct zone_import_ctx zone_import_ctx_t;

static int RRSET_IS_ALREADY_IMPORTED = 1;

/** @internal Allocate zone import context.
 * @return pointer to zone import context or NULL. */
static zone_import_ctx_t *zi_ctx_alloc()
{
	return calloc(1, sizeof(zone_import_ctx_t));
}

/** @internal Free zone import context. */
static void zi_ctx_free(zone_import_ctx_t *z_import)
{
	if (z_import != NULL) {
		free(z_import);
	}
}

/** @internal Reset all fields in the zone import context to their default values.
 * Flushes memory pool, but doesn't reallocate memory pool buffer.
 * Doesn't affect timer handle, pointers to callback and callback parameter.
 * @return 0 if success; -1 if failed. */
static int zi_reset(struct zone_import_ctx *z_import, size_t rrset_sorted_list_size)
{
	mp_flush(z_import->pool.ctx);

	z_import->started = false;
	z_import->start_timestamp = 0;
	z_import->rrset_idx = 0;
	z_import->pool.alloc = (knot_mm_alloc_t) mp_alloc;
	z_import->rrset_indexed = map_make(&z_import->pool);

	array_init(z_import->rrset_sorted);

	int ret = 0;
	if (rrset_sorted_list_size) {
		ret = array_reserve_mm(z_import->rrset_sorted, rrset_sorted_list_size,
				       kr_memreserve, &z_import->pool);
	}

	return ret;
}

/** @internal Close callback for timer handle.
 * @note Actually frees zone import context. */
static void on_timer_close(uv_handle_t *handle)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)handle->data;
	if (z_import != NULL) {
		zi_ctx_free(z_import);
	}
}

zone_import_ctx_t *zi_allocate(struct worker_ctx *worker,
			       zi_callback cb, void *param)
{
	if (worker->loop == NULL) {
		return NULL;
	}
	zone_import_ctx_t *z_import = zi_ctx_alloc();
	if (!z_import) {
		return NULL;
	}
	void *mp = mp_new (8192);
	if (!mp) {
		zi_ctx_free(z_import);
		return NULL;
	}
	z_import->pool.ctx = mp;
	z_import->worker = worker;
	int ret = zi_reset(z_import, 0);
	if (ret < 0) {
		mp_delete(mp);
		zi_ctx_free(z_import);
		return NULL;
	}
	uv_timer_init(z_import->worker->loop, &z_import->timer);
	z_import->timer.data = z_import;
	z_import->cb = cb;
	z_import->cb_param = param;
	return z_import;
}

void zi_free(zone_import_ctx_t *z_import)
{
	z_import->started = false;
	z_import->start_timestamp = 0;
	z_import->rrset_idx = 0;
	mp_delete(z_import->pool.ctx);
	z_import->pool.ctx = NULL;
	z_import->pool.alloc = NULL;
	z_import->worker = NULL;
	z_import->cb = NULL;
	z_import->cb_param = NULL;
	uv_close((uv_handle_t *)&z_import->timer, on_timer_close);
}

/** @internal Mark rrset that has been already imported
 *  to avoid repeated import. */
static inline void zi_rrset_mark_as_imported(knot_rrset_t *rr)
{
	rr->additional = (void *)&RRSET_IS_ALREADY_IMPORTED;
}

/** @internal Check if rrset is marked as "already imported".
 * @return true if marked, false if isn't */
static inline bool zi_rrset_is_marked_as_imported(knot_rrset_t *rr)
{
	return (rr->additional == &RRSET_IS_ALREADY_IMPORTED);
}

/** @internal Try to find rrset with given requisites amongst parsed rrsets
 * and put it to given packet. If there is RRSIG which covers that rrset, it
 * will be added as well. If rrset found and successfully put, it marked as
 * "already imported" to avoid repeated import. The same is true for RRSIG.
 * @return -1 if failed
 *          0 if required record been actually put into the packet
 *          1 if required record could not be found */
static int zi_rrset_find_put(struct zone_import_ctx *z_import,
			     knot_pkt_t *pkt, const knot_dname_t *owner,
			     uint16_t class, uint16_t type, uint16_t additional)
{
	if (type != KNOT_RRTYPE_RRSIG) {
		/* If required rrset isn't rrsig, these must be the same values */
		additional = type;
	}

	char key[KR_RRKEY_LEN];
	int err = kr_rrkey(key, class, owner, type, additional);
	if (err <= 0) {
		return -1;
	}
	knot_rrset_t *rr = map_get(&z_import->rrset_indexed, key);
	if (!rr) {
		return 1;
	}
	err = knot_pkt_put(pkt, 0, rr, 0);
	if (err != KNOT_EOK) {
		return -1;
	}
	zi_rrset_mark_as_imported(rr);

	if (type != KNOT_RRTYPE_RRSIG) {
		/* Try to find corresponding rrsig */
		err = zi_rrset_find_put(z_import, pkt, owner,
					class, KNOT_RRTYPE_RRSIG, type);
		if (err < 0) {
			return err;
		}
	}

	return 0;
}

/** @internal Try to put given rrset to the given packet.
 * If there is RRSIG which covers that rrset, it will be added as well.
 * If rrset successfully put in the packet, it marked as
 * "already imported" to avoid repeated import.
 * The same is true for RRSIG.
 * @return -1 if failed
 *          0 if required record been actually put into the packet */
static int zi_rrset_put(struct zone_import_ctx *z_import, knot_pkt_t *pkt,
			knot_rrset_t *rr)
{
	if (kr_fails_assert(rr && rr->type != KNOT_RRTYPE_RRSIG))
		return -1;
	int err = knot_pkt_put(pkt, 0, rr, 0);
	if (err != KNOT_EOK) {
		return -1;
	}
	zi_rrset_mark_as_imported(rr);
	/* Try to find corresponding RRSIG */
	err = zi_rrset_find_put(z_import, pkt, rr->owner, rr->rclass,
				KNOT_RRTYPE_RRSIG, rr->type);
	return (err < 0) ? err : 0;
}

/** @internal Try to put DS & NSEC* for rset->owner to given packet.
 * @return -1 if failed;
 *          0 if no errors occurred (it doesn't mean
 *            that records were actually added). */
static int zi_put_delegation(zone_import_ctx_t *z_import, knot_pkt_t *pkt,
			     knot_rrset_t *rr)
{
	int err = zi_rrset_find_put(z_import, pkt, rr->owner,
				    rr->rclass, KNOT_RRTYPE_DS, 0);
	if (err == 1) {
		/* DS not found, maybe there are NSEC* */
		err = zi_rrset_find_put(z_import, pkt, rr->owner,
					rr->rclass, KNOT_RRTYPE_NSEC, 0);
		if (err >= 0) {
			err = zi_rrset_find_put(z_import, pkt, rr->owner,
						rr->rclass, KNOT_RRTYPE_NSEC3, 0);
		}
	}
	return err < 0 ? err : 0;
}

/** @internal Try to put A & AAAA records for rset->owner to given packet.
 * @return -1 if failed;
 *          0 if no errors occurred (it doesn't mean
 *            that records were actually added). */
static int zi_put_glue(zone_import_ctx_t *z_import, knot_pkt_t *pkt,
			     knot_rrset_t *rr)
{
	int err = 0;
	knot_rdata_t *rdata_i = rr->rrs.rdata;
	for (uint16_t i = 0; i < rr->rrs.count;
			++i, rdata_i = knot_rdataset_next(rdata_i)) {
		const knot_dname_t *ns_name = knot_ns_name(rdata_i);
		err = zi_rrset_find_put(z_import, pkt, ns_name,
					rr->rclass, KNOT_RRTYPE_A, 0);
		if (err < 0) {
			break;
		}

		err = zi_rrset_find_put(z_import, pkt, ns_name,
					rr->rclass, KNOT_RRTYPE_AAAA, 0);
		if (err < 0) {
			break;
		}
	}
	return err < 0 ? err : 0;
}

/** @internal Create query. */
static knot_pkt_t *zi_query_create(zone_import_ctx_t *z_import, knot_rrset_t *rr)
{
	knot_mm_t *pool = &z_import->pool;

	uint32_t msgid = kr_rand_bytes(2);

	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, pool);
	if (!query) {
		return NULL;
	}

	knot_pkt_put_question(query, rr->owner, rr->rclass, rr->type);
	knot_pkt_begin(query, KNOT_ANSWER);
	knot_wire_set_rd(query->wire);
	knot_wire_set_id(query->wire, msgid);
	int err = knot_pkt_parse(query, 0);
	if (err != KNOT_EOK) {
		knot_pkt_free(query);
		return NULL;
	}

	return query;
}

/** @internal Import given rrset to cache.
 * @return -1 if failed; 0 if success */
static int zi_rrset_import(zone_import_ctx_t *z_import, knot_rrset_t *rr)
{
	/* Create "pseudo query" which asks for given rrset. */
	knot_pkt_t *query = zi_query_create(z_import, rr);
	if (!query) {
		return -1;
	}

	knot_mm_t *pool = &z_import->pool;
	uint8_t *dname = rr->owner;
	uint16_t rrtype = rr->type;
	uint16_t rrclass = rr->rclass;

	/* Create "pseudo answer". */
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, pool);
	if (!answer) {
		knot_pkt_free(query);
		return -1;
	}
	knot_pkt_put_question(answer, dname, rrclass, rrtype);
	knot_pkt_begin(answer, KNOT_ANSWER);

	struct kr_qflags options = { 0 };
	options.DNSSEC_WANT = true;
	options.NO_MINIMIZE = true;

	/* This call creates internal structures which necessary for
	 * resolving - qr_task & request_ctx. */
	struct qr_task *task = worker_resolve_start(query, options);
	if (!task) {
		knot_pkt_free(query);
		knot_pkt_free(answer);
		return -1;
	}

	/* Push query to the request resolve plan.
	 * Actually query will never been sent to upstream. */
	struct kr_request *request = worker_task_request(task);
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_push(rplan, NULL, dname, rrclass, rrtype);
	int state = KR_STATE_FAIL;
	bool origin_is_owner = knot_dname_is_equal(rr->owner, z_import->origin);
	bool is_referral = (rrtype == KNOT_RRTYPE_NS && !origin_is_owner);
	uint32_t msgid = knot_wire_get_id(query->wire);

	qry->id = msgid;

	/* Prepare zonecut. It must have all the necessary requisites for
	 * successful validation - matched zone name & keys & trust-anchors. */
	kr_zonecut_init(&qry->zone_cut, z_import->origin, pool);
	qry->zone_cut.key = z_import->key;
	qry->zone_cut.trust_anchor = z_import->ta;

	if (knot_pkt_init_response(answer, query) != 0) {
		goto cleanup;
	}

	/* Since "pseudo" query asks for NS for subzone,
	 * "pseudo" answer must simulate referral. */
	if (is_referral) {
		knot_pkt_begin(answer, KNOT_AUTHORITY);
	}

	/* Put target rrset to ANSWER\AUTHORIRY as well as corresponding RRSIG */
	int err = zi_rrset_put(z_import, answer, rr);
	if (err != 0) {
		goto cleanup;
	}

	if (!is_referral) {
		knot_wire_set_aa(answer->wire);
	} else {
		/* Type is KNOT_RRTYPE_NS and owner is not equal to origin.
		 * It will be "referral" answer and must contain delegation. */
		err = zi_put_delegation(z_import, answer, rr);
		if (err < 0) {
			goto cleanup;
		}
	}

	knot_pkt_begin(answer, KNOT_ADDITIONAL);

	if (rrtype == KNOT_RRTYPE_NS) {
		/* Try to find glue addresses. */
		err = zi_put_glue(z_import, answer, rr);
		if (err < 0) {
			goto cleanup;
		}
	}

	knot_wire_set_id(answer->wire, msgid);
	answer->parsed = answer->size;
	err = knot_pkt_parse(answer, 0);
	if (err != KNOT_EOK) {
		goto cleanup;
	}

	/* Importing doesn't imply communication with upstream at all.
	 * "answer" contains pseudo-answer from upstream and must be successfully
	 * validated in CONSUME stage. If not, something gone wrong. */
	state = kr_resolve_consume(request, NULL, answer);

cleanup:

	knot_pkt_free(query);
	knot_pkt_free(answer);
	worker_task_finalize(task, state);
	return state == (is_referral ? KR_STATE_PRODUCE : KR_STATE_DONE) ? 0 : -1;
}

/** @internal Create element in qr_rrsetlist_t rrset_list for
 * given node of map_t rrset_sorted.  */
static int zi_mapwalk_preprocess(const char *k, void *v, void *baton)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)baton;

	int ret = array_push_mm(z_import->rrset_sorted, v, kr_memreserve, &z_import->pool);

	return (ret < 0);
}

/** @internal Iterate over parsed rrsets and try to import each of them. */
static void zi_zone_process(uv_timer_t* handle)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)handle->data;

	size_t failed = 0;
	size_t ns_imported = 0;
	size_t other_imported = 0;

	if (kr_fails_assert(z_import->worker)) {
		failed = 1;
		goto finish;
	}

	/* At the moment import of root zone only is supported.
	 * Check the name of the parsed zone.
	 * TODO - implement importing of arbitrary zone. */
	KR_DNAME_GET_STR(zone_name_str, z_import->origin);

	if (strcmp(".", zone_name_str) != 0) {
		kr_log_error(LOG_GRP_ZIMPORT, "[zimport] unexpected zone name `%s` (root zone expected), fail\n",
			     zone_name_str);
		failed = 1;
		goto finish;
	}

	if (z_import->rrset_sorted.len <= 0) {
		kr_log_error(LOG_GRP_ZIMPORT, "[zimport] zone `%s` is empty\n", zone_name_str);
		goto finish;
	}

	/* TA have been found, zone is secured.
	 * DNSKEY must be somewhere amongst the imported records. Find it.
	 * TODO - For those zones that provenly do not have TA this step must be skipped. */
	char key[KR_RRKEY_LEN];
	int err = kr_rrkey(key, KNOT_CLASS_IN, z_import->origin,
			   KNOT_RRTYPE_DNSKEY, KNOT_RRTYPE_DNSKEY);
	if (err <= 0) {
		failed = 1;
		goto finish;
	}

	knot_rrset_t *rr_key = map_get(&z_import->rrset_indexed, key);
	if (!rr_key) {
		/* DNSKEY MUST be here. If not found - fail. */
		kr_log_error(LOG_GRP_ZIMPORT, "[zimport] DNSKEY not found for `%s`, fail\n", zone_name_str);
		failed = 1;
		goto finish;
	}
	z_import->key = rr_key;

	map_t *trust_anchors = &z_import->worker->engine->resolver.trust_anchors;
	knot_rrset_t *rr_ta = kr_ta_get(trust_anchors, z_import->origin);
	if (!rr_ta) {
		kr_log_error(LOG_GRP_ZIMPORT, "[zimport] error: TA for zone `%s` vanished, fail", zone_name_str);
		failed = 1;
		goto finish;
	}
	z_import->ta = rr_ta;

	VERBOSE_MSG(NULL, "started: zone: '%s'\n", zone_name_str);

	z_import->start_timestamp = kr_now();

	/* Import DNSKEY at first step. If any validation problems will appear,
	 * cancel import of whole zone. */
	KR_DNAME_GET_STR(kname_str, rr_key->owner);
	KR_RRTYPE_GET_STR(ktype_str, rr_key->type);

	VERBOSE_MSG(NULL, "importing: name: '%s' type: '%s'\n",
		    kname_str, ktype_str);

	int res = zi_rrset_import(z_import, rr_key);
	if (res != 0) {
		kr_log_error(LOG_GRP_ZIMPORT, "import failed: qname: '%s' type: '%s'\n",
			    kname_str, ktype_str);
		failed = 1;
		goto finish;
	}

	/* Import all NS records */
	for (size_t i = 0; i < z_import->rrset_sorted.len; ++i) {
		knot_rrset_t *rr = z_import->rrset_sorted.at[i];

		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		KR_DNAME_GET_STR(name_str, rr->owner);
		KR_RRTYPE_GET_STR(type_str, rr->type);
		VERBOSE_MSG(NULL, "importing: name: '%s' type: '%s'\n",
			    name_str, type_str);
		int ret = zi_rrset_import(z_import, rr);
		if (ret == 0) {
			++ns_imported;
		} else {
			VERBOSE_MSG(NULL, "import failed: name: '%s' type: '%s'\n",
				    name_str, type_str);
			++failed;
		}
		z_import->rrset_sorted.at[i] = NULL;
	}

	/* NS records have been imported as well as relative DS, NSEC* and glue.
	 * Now import what's left. */
	for (size_t i = 0; i < z_import->rrset_sorted.len; ++i) {

		knot_rrset_t *rr = z_import->rrset_sorted.at[i];
		if (rr == NULL) {
			continue;
		}

		if (zi_rrset_is_marked_as_imported(rr)) {
			continue;
		}

		if (rr->type == KNOT_RRTYPE_DNSKEY || rr->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}

		KR_DNAME_GET_STR(name_str, rr->owner);
		KR_RRTYPE_GET_STR(type_str, rr->type);
		VERBOSE_MSG(NULL, "importing: name: '%s' type: '%s'\n",
			    name_str, type_str);
		res = zi_rrset_import(z_import, rr);
		if (res == 0) {
			++other_imported;
		} else {
			VERBOSE_MSG(NULL, "import failed: name: '%s' type: '%s'\n",
				    name_str, type_str);
			++failed;
		}
	}

	uint64_t elapsed = kr_now() - z_import->start_timestamp;
	elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;

	VERBOSE_MSG(NULL, "finished in %"PRIu64" ms; zone: `%s`; ns: %zd"
		    "; other: %zd; failed: %zd\n",
		    elapsed, zone_name_str, ns_imported, other_imported, failed);

finish:

	uv_timer_stop(&z_import->timer);
	z_import->started = false;

	int import_state = 0;

	if (failed != 0) {
		if (ns_imported == 0 && other_imported == 0) {
			import_state = -1;
			kr_log_error(LOG_GRP_ZIMPORT, "[zimport] import failed; zone `%s` \n", zone_name_str);
		} else {
			import_state = 1;
		}
	} else {
		import_state = 0;
	}

	if (z_import->cb != NULL) {
		z_import->cb(import_state, z_import->cb_param);
	}
}

/** @internal Store rrset that has been imported to zone import context memory pool.
 * @return -1 if failed; 0 if success. */
static int zi_record_store(zs_scanner_t *s)
{
	if (s->r_data_length > UINT16_MAX) {
		/* Due to knot_rrset_add_rdata(..., const uint16_t size, ...); */
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line %"PRIu64": rdata is too long\n",
				s->line_counter);
		return -1;
	}

	if (knot_dname_size(s->r_owner) != strlen((const char *)(s->r_owner)) + 1) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line %"PRIu64
				": owner name contains zero byte, skip\n",
				s->line_counter);
		return 0;
	}

	zone_import_ctx_t *z_import = (zone_import_ctx_t *)s->process.data;

	knot_rrset_t *new_rr = knot_rrset_new(s->r_owner, s->r_type, s->r_class,
					      s->r_ttl, &z_import->pool);
	if (!new_rr) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line %"PRIu64": error creating rrset\n",
				s->line_counter);
		return -1;
	}
	int res = knot_rrset_add_rdata(new_rr, s->r_data, s->r_data_length,
				       &z_import->pool);
	if (res != KNOT_EOK) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line %"PRIu64": error adding rdata to rrset\n",
				s->line_counter);
		return -1;
	}

	/* Records in zone file may not be grouped by name and RR type.
	 * Use map to create search key and
	 * avoid ineffective searches across all the imported records. */
	char key[KR_RRKEY_LEN];
	uint16_t additional_key_field = kr_rrset_type_maysig(new_rr);

	res = kr_rrkey(key, new_rr->rclass, new_rr->owner, new_rr->type,
		       additional_key_field);
	if (res <= 0) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line %"PRIu64": error constructing rrkey\n",
				s->line_counter);
		return -1;
	}

	knot_rrset_t *saved_rr = map_get(&z_import->rrset_indexed, key);
	if (saved_rr) {
		res = knot_rdataset_merge(&saved_rr->rrs, &new_rr->rrs,
					  &z_import->pool);
	} else {
		res = map_set(&z_import->rrset_indexed, key, new_rr);
	}
	if (res != 0) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line %"PRIu64": error saving parsed rrset\n",
				s->line_counter);
		return -1;
	}

	return 0;
}

/** @internal zscanner callback. */
static int zi_state_parsing(zs_scanner_t *s)
{
	bool empty = true;
	while (zs_parse_record(s) == 0) {
		switch (s->state) {
		case ZS_STATE_DATA:
			if (zi_record_store(s) != 0) {
				return -1;
			}
			zone_import_ctx_t *z_import = (zone_import_ctx_t *) s->process.data;
			empty = false;
			if (s->r_type == 6) {
				z_import->origin = knot_dname_copy(s->r_owner,
                                                                 &z_import->pool);
			}
			break;
		case ZS_STATE_ERROR:
			kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line: %"PRIu64
				     ": parse error; code: %i ('%s')\n",
				     s->line_counter, s->error.code,
				     zs_strerror(s->error.code));
			return -1;
		case ZS_STATE_INCLUDE:
			kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] line: %"PRIu64
				     ": INCLUDE is not supported\n",
				     s->line_counter);
			return -1;
		case ZS_STATE_EOF:
		case ZS_STATE_STOP:
			if (empty) {
				kr_log_error(LOG_GRP_ZIMPORT, "[zimport] empty zone file\n");
				return -1;
			}
			if (!((zone_import_ctx_t *) s->process.data)->origin) {
				kr_log_error(LOG_GRP_ZIMPORT, "[zimport] zone file doesn't contain SOA record\n");
				return -1;
			}
			return (s->error.counter == 0) ? 0 : -1;
		default:
			kr_log_error(LOG_GRP_ZSCANNER, "[zimport] line: %"PRIu64
				     ": unexpected parse state: %i\n",
				     s->line_counter, s->state);
			return -1;
		}
	}

	return -1;
}

int zi_zone_import(struct zone_import_ctx *z_import,
		   const char *zone_file, const char *origin,
		   uint16_t rclass, uint32_t ttl)
{
	if (kr_fails_assert(z_import && z_import->worker && zone_file))
		return -1;

	zs_scanner_t *s = malloc(sizeof(zs_scanner_t));
	if (s == NULL) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] error creating instance of zone scanner (malloc() fails)\n");
		return -1;
	}

	/* zs_init(), zs_set_input_file(), zs_set_processing() returns -1 in case of error,
	 * so don't print error code as it meaningless. */
	int res = zs_init(s, origin, rclass, ttl);
	if (res != 0) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] error initializing zone scanner instance, error: %i (%s)\n",
			     s->error.code, zs_strerror(s->error.code));
		free(s);
		return -1;
	}

	res = zs_set_input_file(s, zone_file);
	if (res != 0) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] error opening zone file `%s`, error: %i (%s)\n",
			     zone_file, s->error.code, zs_strerror(s->error.code));
		zs_deinit(s);
		free(s);
		return -1;
	}

	/* Don't set processing and error callbacks as we don't use automatic parsing.
	 * Parsing as well error processing will be performed in zi_state_parsing().
	 * Store pointer to zone import context for further use. */
	if (zs_set_processing(s, NULL, NULL, (void *)z_import) != 0) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] zs_set_processing() failed for zone file `%s`, "
				"error: %i (%s)\n",
				zone_file, s->error.code, zs_strerror(s->error.code));
		zs_deinit(s);
		free(s);
		return -1;
	}

	uint64_t elapsed = 0;
	int ret = zi_reset(z_import, 4096);
	if (ret == 0) {
		z_import->started = true;
		z_import->start_timestamp = kr_now();
		VERBOSE_MSG(NULL, "[zscanner] started; zone file `%s`\n",
			    zone_file);
		ret = zi_state_parsing(s);
		if (ret == 0) {
			/* Try to find TA for worker->z_import.origin. */
			map_t *trust_anchors = &z_import->worker->engine->resolver.trust_anchors;
			knot_rrset_t *rr = kr_ta_get(trust_anchors, z_import->origin);
			if (!rr) {
				/* For now - fail.
				 * TODO - query DS and continue after answer had been obtained. */
				KR_DNAME_GET_STR(zone_name_str, z_import->origin);
				kr_log_error(LOG_GRP_ZIMPORT, "[zimport] no TA found for `%s`, fail\n", zone_name_str);
				ret = 1;
			}
			elapsed = kr_now() - z_import->start_timestamp;
			elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;
		}
	}
	zs_deinit(s);
	free(s);

	if (ret != 0) {
		kr_log_error(LOG_GRP_ZSCANNER, "[zscanner] error parsing zone file `%s`\n", zone_file);
		z_import->started = false;
		return ret;
	}

	VERBOSE_MSG(NULL, "[zscanner] finished in %"PRIu64" ms; zone file `%s`\n",
			    elapsed, zone_file);
	map_walk(&z_import->rrset_indexed, zi_mapwalk_preprocess, z_import);

	/* Zone have been parsed already, so start the import. */
	uv_timer_start(&z_import->timer, zi_zone_process,
		       ZONE_IMPORT_PAUSE, ZONE_IMPORT_PAUSE);

	return 0;
}

bool zi_import_started(struct zone_import_ctx *z_import)
{
	return z_import ? z_import->started : false;
}
