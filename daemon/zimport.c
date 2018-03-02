/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <uv.h>
#include <ucw/mempool.h>
#include <libknot/rrset.h>
#include <zscanner/scanner.h>

#include "lib/utils.h"
#include "lib/dnssec/ta.h"
#include "daemon/worker.h"
#include "daemon/zimport.h"
#include "lib/generic/map.h"
#include "lib/generic/array.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "zimport", fmt)

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
	map_t rrset_sorted;
	qr_rrsetlist_t rrset_list;
	knot_mm_t pool;
	zi_callback cb;
	void *cb_param;
};

typedef struct zone_import_ctx zone_import_ctx_t;

int worker_task_finalize(struct qr_task *task, int state);

static int RRSET_IS_ALREADY_IMPORTED = 1;

/** @internal Allocate zone import context.
 * @return pointer to zone import context or NULL. */
static zone_import_ctx_t *zi_ctx_alloc()
{
	return (zone_import_ctx_t *)malloc(sizeof(zone_import_ctx_t));
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
static int zi_reset(struct zone_import_ctx *z_import, size_t rrset_list_size)
{
	mp_flush(z_import->pool.ctx);

	z_import->started = false;
	z_import->start_timestamp = 0;
	z_import->rrset_idx = 0;
	z_import->pool.alloc = (knot_mm_alloc_t) mp_alloc;
	z_import->rrset_sorted = map_make(&z_import->pool);

	array_init(z_import->rrset_list);

	int ret = 0;
	if (rrset_list_size) {
		ret = array_reserve_mm(z_import->rrset_list, rrset_list_size,
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
	memset(z_import, 0, sizeof(*z_import));
	z_import->pool.ctx = mp;
	z_import->worker = worker;
	int ret = zi_reset(z_import, 0);
	if (ret < 0) {
		mp_delete(mp);
		zi_ctx_free(z_import);
		z_import = NULL;
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

/** @internal Try to find rrset with required properties amongst parsed rrsets
 * and put it to given packet, If rrset found and successfully put, it marked as
 * "already imported" to avoid repeated import.
 * @return -1 if failed
 *          0 if required record been actually put into the packet
 *          1 if required record could not be found */
static int zi_put_supplementary(struct zone_import_ctx *z_import,
				knot_pkt_t *pkt, const knot_dname_t *owner,
				uint16_t class, uint16_t supp_type)
{
	assert(supp_type != KNOT_RRTYPE_RRSIG);

	char key[KR_RRKEY_LEN];
	int err = kr_rrkey(key, class, owner, supp_type, supp_type);
	if (err <= 0) {
		return -1;
	}
	knot_rrset_t *additional_rr = map_get(&z_import->rrset_sorted, key);
	err = kr_rrkey(key, class, owner, KNOT_RRTYPE_RRSIG, supp_type);
	if (err <= 0) {
		return -1;
	}
	knot_rrset_t *rrsig = map_get(&z_import->rrset_sorted, key);
	if (additional_rr) {
		err = knot_pkt_put(pkt, 0, additional_rr, 0);
		if (err != KNOT_EOK) {
			return -1;
		}
		zi_rrset_mark_as_imported(additional_rr);
	}
	if (rrsig) {
		err = knot_pkt_put(pkt, 0, rrsig, 0);
		if (err != KNOT_EOK) {
			return -1;
		}
		zi_rrset_mark_as_imported(rrsig);
	}
	return additional_rr == NULL ? 1 : 0;
}

/** @internal Import given rrset to cache.
 * The main goal of import procedure is to store parsed records to the cache.
 * Resolver imports rrset by creating request that will never be sent to upstream.
 * After request creation resolver creates pseudo-answer which must contain
 * all necessary data for validation. Then resolver process answer as if he had
 * been received from network.
 * @return -1 if failed; 0 if success */
static int zi_rrset_import(zone_import_ctx_t *z_import, knot_rrset_t *rr)
{
	struct worker_ctx *worker = z_import->worker;

	assert(worker);

	knot_mm_t *pool = &z_import->pool;

	uint8_t *dname = rr->owner;
	uint16_t rrtype = rr->type;
	uint16_t rrclass = rr->rclass;

	struct kr_qflags options;
	memset(&options, 0, sizeof(options));
	options.DNSSEC_WANT = true;
	options.NO_MINIMIZE = true;
	uint32_t msgid = kr_rand_uint(0);

	/* Create query */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, pool);
	if (!query) {
		return -1;
	}
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, pool);
	if (!answer) {
		knot_pkt_free(&query);
		return -1;
	}

	knot_pkt_put_question(query, dname, rrclass, rrtype);
	knot_pkt_begin(query, KNOT_ANSWER);
	knot_wire_set_rd(query->wire);
	knot_wire_set_id(query->wire, msgid);

	struct qr_task *task = worker_resolve_start(worker, query, options);
	if (!task) {
		knot_pkt_free(&query);
		knot_pkt_free(&answer);
		return -1;
	}

	struct kr_request *request = worker_task_request(task);
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *qry = kr_rplan_push(rplan, NULL, dname, rrclass, rrtype);
	char key[KR_RRKEY_LEN];
	int err = 0;
	int state = KR_STATE_FAIL;
	bool origin_is_owner = knot_dname_is_equal(rr->owner, z_import->origin);
	bool is_referral = (rrtype == KNOT_RRTYPE_NS && !origin_is_owner);

	qry->id = msgid;
	kr_zonecut_init(&qry->zone_cut, z_import->origin, pool);
	qry->zone_cut.key = z_import->key;
	qry->zone_cut.trust_anchor = z_import->ta;

	if (knot_pkt_init_response(request->answer, query) != 0) {
		goto cleanup;
	}

	knot_pkt_put_question(answer, dname, rrclass, rrtype);
	knot_pkt_begin(answer, KNOT_ANSWER);

	if (is_referral) {
		knot_pkt_begin(answer, KNOT_AUTHORITY);
	}

	err = knot_pkt_put(answer, 0, rr, 0);
	if (err != 0) {
		goto cleanup;
	}
	zi_rrset_mark_as_imported(rr);

	err = kr_rrkey(key, rr->rclass, rr->owner, KNOT_RRTYPE_RRSIG, rr->type);
	if (err <= 0) {
		goto cleanup;
	}
	knot_rrset_t *rrsig = map_get(&z_import->rrset_sorted, key);
	if (rrsig) {
		err = knot_pkt_put(answer, 0, rrsig, 0);
		if (err != 0) {
			goto cleanup;
		}
		zi_rrset_mark_as_imported(rrsig);
	}

	if (!is_referral) {
		knot_wire_set_aa(answer->wire);
	} else {
		/* Type is KNOT_RRTYPE_NS and owner is not equal to origin.
		 * It will be "referral" answer, so try to add DS or NSEC* to it. */
		err = zi_put_supplementary(z_import, answer, rr->owner,
					   rr->rclass, KNOT_RRTYPE_DS);
		if (err < 0) {
			goto cleanup;
		} else if (err == 1) {
			/* DS not found */
			err = zi_put_supplementary(z_import, answer, rr->owner,
						   rr->rclass, KNOT_RRTYPE_NSEC);
			if (err < 0) {
				goto cleanup;
			}
			err = zi_put_supplementary(z_import, answer, rr->owner,
						   rr->rclass, KNOT_RRTYPE_NSEC3);
			if (err < 0) {
				goto cleanup;
			}
		}
	}

	knot_pkt_begin(answer, KNOT_ADDITIONAL);

	if (rrtype == KNOT_RRTYPE_NS) {
		/* Try to find glue addresses. */
		for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
			const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, i);
			err = zi_put_supplementary(z_import, answer, ns_name,
						   rr->rclass, KNOT_RRTYPE_A);
			if (err < 0) {
				goto cleanup;
			}

			err = zi_put_supplementary(z_import, answer, ns_name,
						   rr->rclass, KNOT_RRTYPE_AAAA);
			if (err < 0) {
				goto cleanup;
			}
		}
	}

	knot_wire_set_id(answer->wire, msgid);
	answer->parsed = answer->size;

	/* Importing doesn't imply communication with upstream at all.
	 * "answer" contains pseudo-answer from upstream and must be successfully
	 * validated in CONSUME stage. If not, something gone wrong. */
	state = kr_resolve_consume(request, NULL, answer);

cleanup:

	knot_pkt_free(&query);
	knot_pkt_free(&answer);
	worker_task_finalize(task, state);
	return state == (is_referral ? KR_STATE_PRODUCE : KR_STATE_DONE) ? 0 : -1;
}

/** @internal Create element in qr_rrsetlist_t rrset_list for
 * given node of map_t rrset_sorted.  */
static int zi_mapwalk_preprocess(const char *k, void *v, void *baton)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)baton;

	int ret = array_push_mm(z_import->rrset_list, v, kr_memreserve, &z_import->pool);

	return (ret < 0);
}

/** @internal Iterate over parsed rrsets and try to import each of them. */
static void zi_zone_process(uv_timer_t* handle)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)handle->data;

	assert(z_import->worker);

	size_t failed = 0;
	size_t ns_imported = 0;
	size_t other_imported = 0;

	/* At the moment import of root zone only is supported.
	 * Check the name of the parsed zone.
	 * TODO - implement importing of arbitrary zone. */
	char zone_name_str[KNOT_DNAME_MAXLEN];
	knot_dname_to_str(zone_name_str, z_import->origin, sizeof(zone_name_str));
	if (strcmp(".", zone_name_str) != 0) {
		kr_log_error("[zimport] unexpected zone name `%s` (root zone expected), fail\n",
			     zone_name_str);
		failed = 1;
		goto finish;
	}

	if (z_import->rrset_list.len <= 0) {
		VERBOSE_MSG(NULL, "zone is empty\n");
		goto finish;
	}

	/* z_import.rrset_list now contains sorted rrset list.
	 * Records are sorted by the key returned by kr_rrkey() function.
	 * Find out if zone is secured.
	 * Try to find TA for worker->z_import.origin. */
	map_t *trust_anchors = &z_import->worker->engine->resolver.trust_anchors;
	knot_rrset_t *rr = kr_ta_get(trust_anchors, z_import->origin);
	if (!rr) {
		/* For now - fail.
		 * TODO - query DS and continue after answer had been obtained. */
		kr_log_error("[zimport] TA not found for `%s`, fail\n", zone_name_str);
		failed = 1;
		goto finish;
	}
	z_import->ta = rr;

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

	rr = map_get(&z_import->rrset_sorted, key);
	if (!rr) {
		/* DNSKEY MUST be here. If not found - fail. */
		kr_log_error("[zimport] DNSKEY not found for `%s`, fail\n", zone_name_str);
		failed = 1;
		goto finish;
	}
	z_import->key = rr;

	VERBOSE_MSG(NULL, "started: zone: '%s'\n", zone_name_str);

	z_import->start_timestamp = kr_now();

	/* Import DNSKEY at first step. If any validation problems will appear,
	 * cancel import of whole zone. */
	char qname_str[KNOT_DNAME_MAXLEN], type_str[16];
	knot_dname_to_str(qname_str, rr->owner, sizeof(qname_str));
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	VERBOSE_MSG(NULL, "importing: qname: '%s' type: '%s'\n",
		    qname_str, type_str);

	int res = zi_rrset_import(z_import, rr);
	if (res != 0) {
		VERBOSE_MSG(NULL, "import failed: qname: '%s' type: '%s'\n",
			    qname_str, type_str);
		failed = 1;
		goto finish;
	}

	/* Import all NS records */
	for (size_t i = 0; i < z_import->rrset_list.len; ++i) {
		knot_rrset_t *rr = z_import->rrset_list.at[i];

		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		knot_dname_to_str(qname_str, rr->owner, sizeof(qname_str));
		knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
		VERBOSE_MSG(NULL, "importing: qname: '%s' type: '%s'\n",
			    qname_str, type_str);
		int res = zi_rrset_import(z_import, rr);
		if (res == 0) {
			++ns_imported;
		} else {
			VERBOSE_MSG(NULL, "import failed: qname: '%s' type: '%s'\n",
				    qname_str, type_str);
			++failed;
		}
		z_import->rrset_list.at[i] = NULL;
	}

	/* NS records have been imported as well as relative DS, NSEC* and glue.
	 * Now import what's left. */
	for (size_t i = 0; i < z_import->rrset_list.len; ++i) {

		knot_rrset_t *rr = z_import->rrset_list.at[i];
		if (rr == NULL) {
			continue;
		}

		if (zi_rrset_is_marked_as_imported(rr)) {
			continue;
		}

		if (rr->type == KNOT_RRTYPE_DNSKEY || rr->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}

		knot_dname_to_str(qname_str, rr->owner, sizeof(qname_str));
		knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
		VERBOSE_MSG(NULL, "importing: qname: '%s' type: '%s'\n",
			    qname_str, type_str);
		res = zi_rrset_import(z_import, rr);
		if (res == 0) {
			++other_imported;
		} else {
			VERBOSE_MSG(NULL, "import failed: qname: '%s' type: '%s'\n",
				    qname_str, type_str);
			++failed;
		}
	}

	uint64_t elapsed = kr_now() - z_import->start_timestamp;
	elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;

	VERBOSE_MSG(NULL, "finished in %lu ms; zone: `%s`; ns: %zd; other: %zd; failed: %zd\n",
		    elapsed, zone_name_str, ns_imported, other_imported, failed);

finish:

	uv_timer_stop(&z_import->timer);
	z_import->started = false;

	int import_state = 0;

	if (failed != 0) {
		if (ns_imported == 0 && other_imported == 0) {
			import_state = -1;
			VERBOSE_MSG(NULL, "import failed; zone `%s` \n", zone_name_str);
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
		kr_log_error("[zscanner] line %lu: rdata is too long\n", s->line_counter);
		return -1;
	}

	if (knot_dname_size(s->r_owner) != strlen((const char *)(s->r_owner)) + 1) {
		kr_log_error("[zscanner] line %lu: owner name contains zero byte, skip\n", s->line_counter);
		return 0;
	}

	zone_import_ctx_t *z_import = (zone_import_ctx_t *)s->process.data;

	knot_rrset_t *new_rr = knot_rrset_new(s->r_owner, s->r_type, s->r_class,
					      &z_import->pool);
	if (!new_rr) {
		kr_log_error("[zscanner] line %lu: error creating rrset\n", s->line_counter);
		return -1;
	}
	int ret = knot_rrset_add_rdata(new_rr, s->r_data, s->r_data_length,
				       s->r_ttl, &z_import->pool);
	if (ret != KNOT_EOK) {
		kr_log_error("[zscanner] line %lu: error adding rdata to rrset\n", s->line_counter);
		return -1;
	}

	char key[KR_RRKEY_LEN];
	uint16_t additional_key_field = kr_rrset_type_maysig(new_rr);

	ret = kr_rrkey(key, new_rr->rclass, new_rr->owner, new_rr->type,
		       additional_key_field);
	if (ret <= 0) {
		kr_log_error("[zscanner] line %lu: error constructing rrkey\n", s->line_counter);
		return -1;
	}

	knot_rrset_t *saved_rr = map_get(&z_import->rrset_sorted, key);
	if (saved_rr) {
		ret = knot_rdataset_merge(&saved_rr->rrs, &new_rr->rrs,
					  &z_import->pool);
	} else {
		ret = map_set(&z_import->rrset_sorted, key, new_rr);
	}
	if (ret != 0) {
		kr_log_error("[zscanner] line %lu: error saving parsed rrset\n", s->line_counter);
		return -1;
	}

	return 0;
}

/** @internal zscanner callback. */
static int zi_state_parsing(zs_scanner_t *s)
{
	while (zs_parse_record(s) == 0) {
		switch (s->state) {
		case ZS_STATE_DATA:
			if (zi_record_store(s) != 0) {
				return -1;
			}
			zone_import_ctx_t *z_import = (zone_import_ctx_t *) s->process.data;
			if (z_import->origin == 0) {
				z_import->origin = knot_dname_copy(s->zone_origin,
								  &z_import->pool);
			} else if (!knot_dname_is_equal(z_import->origin, s->zone_origin)) {
				kr_log_error("[zscanner] line: %lu: zone origin changed unexpectedly\n",
					     s->line_counter);
				return -1;
			}
			break;
		case ZS_STATE_ERROR:
			kr_log_error("[zscanner] line: %lu: error parsing record\n", s->line_counter);
			return -1;
			break;
		case ZS_STATE_INCLUDE:
			return -1;
			break;
		default:
			return (s->error.counter == 0) ? 0 : -1;
		}
	}

	return -1;
}

int zi_zone_import(struct zone_import_ctx *z_import,
		   const char *zone_file, const char *origin,
		   uint16_t rclass, uint32_t ttl)
{
	if (z_import->worker == NULL) {
		kr_log_error("[zscanner] invalid <z_import> parameter\n");
		return -1;
	}

	zs_scanner_t *s = malloc(sizeof(zs_scanner_t));
	if (s == NULL) {
		kr_log_error("[zscanner] error creating instance of zone scanner\n");
		return -1;
	}

	if (zs_init(s, origin, rclass, ttl) != 0) {
		free(s);
		kr_log_error("[zscanner] error initializing zone scanner instance\n");
		return -1;
	}

	if (zs_set_input_file(s, zone_file) != 0) {
		zs_deinit(s);
		free(s);
		kr_log_error("[zscanner] error opening zone file `%s`\n", zone_file);
		return -1;
	}

	/* Don't set callbacks as we don't use automatic parsing.
	 * Store pointer to zone import context. */
	if (zs_set_processing(s, NULL, NULL, (void *)z_import) != 0) {
		zs_deinit(s);
		free(s);
		kr_log_error("[zscanner] error opening zone file `%s`\n", zone_file);
		return -1;
	}

	/* To reduce time spent in the callback, import is split
	 * into two stages. In the first stage zone file is parsed and prepared
	 * for importing to cache. In the second stage parsed zone is imported
	 * into the cache. Since root zone isn't large it is imported as single
	 * chunk. If it would be considered as necessary, second stage can be
	 * split into shorter stages. */

	uint64_t elapsed = 0;
	int ret = zi_reset(z_import, 4096);
	if (ret == 0) {
		z_import->started = true;
		z_import->start_timestamp = kr_now();
		VERBOSE_MSG(NULL, "[zscanner] started; zone file `%s`\n",
			    zone_file);
		ret = zi_state_parsing(s);
		elapsed = kr_now() - z_import->start_timestamp;
		elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;
	}
	zs_deinit(s);
	free(s);

	if (ret != 0) {
		kr_log_error("[zscanner] error parsing zone file `%s`\n", zone_file);
		z_import->started = false;
		return ret;
	}

	VERBOSE_MSG(NULL, "[zscanner] finished in %lu ms; zone file `%s`\n",
			    elapsed, zone_file);

	map_walk(&z_import->rrset_sorted, zi_mapwalk_preprocess, z_import);

	/* Start import */
	uv_timer_start(&z_import->timer, zi_zone_process,
		       ZONE_IMPORT_PAUSE, ZONE_IMPORT_PAUSE);

	return 0;
}

bool zi_import_started(struct zone_import_ctx *z_import)
{
	return z_import ? z_import->started : false;
}
