/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* Module is intended to import resource records from file into resolver's cache.
 * File supposed to be a standard DNS zone file
 * which contains text representations of resource records.
 * For now only root zone import is supported.
 *
 * Import process consists of two stages.
 * 1) Zone file parsing and (optionally) ZONEMD verification.
 * 2) DNSSEC validation and storage in cache.
 *
 * These stages are implemented as two separate functions
 * (zi_zone_import and zi_zone_process) which run sequentially with a
 * pause between them. This is done because resolver is a single-threaded
 * application, so it can't process user's requests during the whole import
 * process. Separation into two stages allows to reduce the
 * continuous time interval when resolver can't serve user requests.
 * Since root zone isn't large, it is imported as single chunk.
 */

#include "daemon/zimport.h"

#include <inttypes.h> /* PRIu64 */
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <uv.h>

#include "contrib/ucw/mempool.h"
#include <libknot/rrset.h>
#include <libzscanner/scanner.h>

#include <libknot/version.h>
#define ENABLE_ZONEMD (KNOT_VERSION_HEX >= 0x030100)
#if ENABLE_ZONEMD
	#include <libdnssec/digest.h>

	#if KNOT_VERSION_HEX < 0x030200
		#define KNOT_ZONEMD_ALGORITHM_SHA384 KNOT_ZONEMD_ALORITHM_SHA384
		#define KNOT_ZONEMD_ALGORITHM_SHA512 KNOT_ZONEMD_ALORITHM_SHA512
	#endif
#endif

#include "daemon/worker.h"
#include "lib/dnssec/ta.h"
#include "lib/dnssec.h"
#include "lib/generic/map.h"
#include "lib/generic/array.h"
#include "lib/generic/trie.h"
#include "lib/utils.h"

/* Pause between parse and import stages, milliseconds. */
#define ZONE_IMPORT_PAUSE 100

// NAN normally comes from <math.h> but it's not guaranteed.
#ifndef NAN
	#define NAN nan("")
#endif

struct zone_import_ctx {
	knot_mm_t *pool; /// memory pool for all allocations (including struct itself)
	knot_dname_t *origin;
	uv_timer_t timer;

	// from zi_config_t
	zi_callback cb;
	void *cb_param;

	trie_t *rrsets; /// map: key_get() -> knot_rrset_t*, in ZONEMD order
	uint32_t timestamp_rr; /// stamp of when RR data arrived (seconds since epoch)

	struct kr_svldr_ctx *svldr; /// DNSSEC validator; NULL iff we don't validate
	const knot_dname_t *last_cut; /// internal to zi_rrset_import()

#if ENABLE_ZONEMD
	uint8_t *digest_buf; /// temporary buffer for digest computation (on pool)
	#define DIGEST_BUF_SIZE (64*1024 - 1)
	#define DIGEST_ALG_COUNT 2
	struct {
		bool active; /// whether we want it computed
		dnssec_digest_ctx_t *ctx;
		const uint8_t *expected; /// expected digest (inside zonemd on pool)
	} digests[DIGEST_ALG_COUNT]; /// we use indices 0 and 1 for SHA 384 and 512
#endif
};

typedef struct zone_import_ctx zone_import_ctx_t;


#define KEY_LEN (KNOT_DNAME_MAXLEN + 1 + 2 + 2)
/** Construct key for name, type and signed type (if type == RRSIG).
 *
 * Return negative error code in asserted cases.
 */
static int key_get(char buf[KEY_LEN], const knot_dname_t *name,
		uint16_t type, uint16_t type_maysig, char **key_p)
{
	char *lf = (char *)knot_dname_lf(name, (uint8_t *)buf);
	if (kr_fails_assert(lf && key_p))
		return kr_error(EINVAL);
	int len = lf[0];
	lf++;  // point to start of data
	*key_p = lf;
	// Check that LF is right-aligned to KNOT_DNAME_MAXLEN in buf.
	if (kr_fails_assert(lf + len == buf + KNOT_DNAME_MAXLEN))
		return kr_error(EINVAL);
	buf[KNOT_DNAME_MAXLEN] = 0;  // this ensures correct ZONEMD order
	memcpy(buf + KNOT_DNAME_MAXLEN + 1, &type, sizeof(type));
	len += 1 + sizeof(type);
	if (type == KNOT_RRTYPE_RRSIG) {
		memcpy(buf + KNOT_DNAME_MAXLEN + 1 + sizeof(type),
			&type_maysig, sizeof(type_maysig));
		len += sizeof(type_maysig);
	}
	return len;
}

/** Simple helper to retreive from zone_import_ctx_t::rrsets */
static knot_rrset_t * rrset_get(trie_t *rrsets, const knot_dname_t *name,
				uint16_t type, uint16_t type_maysig)
{
	char key_buf[KEY_LEN], *key;
	const int len = key_get(key_buf, name, type, type_maysig, &key);
	if (len < 0)
		return NULL;
	const trie_val_t *rrsig_p = trie_get_try(rrsets, key, len);
	if (!rrsig_p)
		return NULL;
	kr_assert(*rrsig_p);
	return *rrsig_p;
}

#if ENABLE_ZONEMD
static int digest_rrset(trie_val_t *rr_p, void *z_import_v)
{
	zone_import_ctx_t *z_import = z_import_v;
	const knot_rrset_t *rr = *rr_p;

	// ignore apex ZONEMD or its RRSIG, and also out of bailiwick records
	const int origin_bailiwick = knot_dname_in_bailiwick(rr->owner, z_import->origin);
	const bool is_apex = origin_bailiwick == 0;
	if (is_apex && kr_rrset_type_maysig(rr) == KNOT_RRTYPE_ZONEMD)
		return KNOT_EOK;
	if (unlikely(origin_bailiwick < 0))
		return KNOT_EOK;

	const int len = knot_rrset_to_wire_extra(rr, z_import->digest_buf, DIGEST_BUF_SIZE,
						 0, NULL, KNOT_PF_ORIGTTL);
	if (len < 0)
		return kr_error(len);

	// digest serialized RRSet
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		if (!z_import->digests[i].active)
			continue;
		dnssec_binary_t bufbin = { len, z_import->digest_buf };
		int ret = dnssec_digest(z_import->digests[i].ctx, &bufbin);
		if (ret != KNOT_EOK)
			return kr_error(ret);
	}
	return KNOT_EOK;
}

/** Verify ZONEMD in the stored zone, and return error code.
 *
 * ZONEMD signature is verified iff z_import->svldr != NULL
   https://www.rfc-editor.org/rfc/rfc8976.html#name-verifying-zone-digest
 */
static int zonemd_verify(zone_import_ctx_t *z_import)
{
	bool zonemd_is_valid = false;
	// Find ZONEMD RR + RRSIG
	knot_rrset_t * const rr_zonemd
		= rrset_get(z_import->rrsets, z_import->origin, KNOT_RRTYPE_ZONEMD, 0);
	if (!rr_zonemd) {
		// no zonemd; let's compute the shorter digest and print info later
		z_import->digests[KNOT_ZONEMD_ALGORITHM_SHA384 - 1].active = true;
		goto do_digest;
	}
	// Validate ZONEMD RRSIG, if desired
	if (z_import->svldr) {
		const knot_rrset_t *rrsig_zonemd
			= rrset_get(z_import->rrsets, z_import->origin,
					KNOT_RRTYPE_RRSIG, KNOT_RRTYPE_ZONEMD);
		int ret = rrsig_zonemd
			? kr_svldr_rrset(rr_zonemd, &rrsig_zonemd->rrs, z_import->svldr)
			: kr_error(ENOENT);
		zonemd_is_valid = (ret == kr_ok());

		if (!rrsig_zonemd) {
			kr_log_error(PREFILL, "ZONEMD signature missing\n");
		} else if (!zonemd_is_valid) {
			kr_log_error(PREFILL, "ZONEMD signature failed to validate\n");
		}
	}

	// Get SOA serial
	const knot_rrset_t *soa = rrset_get(z_import->rrsets, z_import->origin,
						KNOT_RRTYPE_SOA, 0);
	if (!soa) {
		kr_log_error(PREFILL, "SOA record not found\n");
		return kr_error(ENOENT);
	}
	if (soa->rrs.count != 1) {
		kr_log_error(PREFILL, "the SOA RR set is weird\n");
		return kr_error(EINVAL);
	} // length is checked by parser already
	const uint32_t soa_serial = knot_soa_serial(soa->rrs.rdata);

	// Figure out SOA+ZONEMD RR contents.
	bool some_active = false;
	knot_rdata_t *rd = rr_zonemd->rrs.rdata;
	for (int i = 0; i < rr_zonemd->rrs.count; ++i, rd = knot_rdataset_next(rd)) {
		if (rd->len < 6 || knot_zonemd_scheme(rd) != KNOT_ZONEMD_SCHEME_SIMPLE
		    || knot_zonemd_soa_serial(rd) != soa_serial)
			continue;
		const int algo = knot_zonemd_algorithm(rd);
		if (algo != KNOT_ZONEMD_ALGORITHM_SHA384 && algo != KNOT_ZONEMD_ALGORITHM_SHA512)
			continue;
		if (rd->len != 6 + knot_zonemd_digest_size(rd)) {
			kr_log_error(PREFILL, "ZONEMD record has incorrect digest length\n");
			return kr_error(EINVAL);
		}
		if (z_import->digests[algo - 1].active) {
			kr_log_error(PREFILL, "multiple clashing ZONEMD records found\n");
			return kr_error(EINVAL);
		}
		some_active = true;
		z_import->digests[algo - 1].active = true;
		z_import->digests[algo - 1].expected = knot_zonemd_digest(rd);
	}
	if (!some_active) {
		kr_log_error(PREFILL, "ZONEMD record(s) found but none were usable\n");
		return kr_error(ENOENT);
	}
do_digest:
	// Init memory, etc.
	if (!z_import->digest_buf) {
		z_import->digest_buf = mm_alloc(z_import->pool, DIGEST_BUF_SIZE);
		if (!z_import->digest_buf)
			return kr_error(ENOMEM);
	}
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		const int algo = i + 1;
		if (!z_import->digests[i].active)
			continue;
		int ret = dnssec_digest_init(algo, &z_import->digests[i].ctx);
		if (ret != KNOT_EOK) {
			// free previous successful _ctx, if applicable
			dnssec_binary_t digest = { 0 };
			while (--i >= 0) {
				if (z_import->digests[i].active)
					dnssec_digest_finish(z_import->digests[i].ctx,
								&digest);
			}
			return kr_error(ENOMEM);
		}
	}
	// Actually compute the digest(s).
	int ret = trie_apply(z_import->rrsets, digest_rrset, z_import);
	dnssec_binary_t digs[DIGEST_ALG_COUNT] = { { 0 } };
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		if (!z_import->digests[i].active)
			continue;
		int ret2 = dnssec_digest_finish(z_import->digests[i].ctx, &digs[i]);
		if (ret == DNSSEC_EOK)
			ret = ret2;
		// we need to keep going to free all digests[*].ctx
	}
	if (ret != DNSSEC_EOK) {
		for (int i = 0; i < DIGEST_ALG_COUNT; ++i)
			free(digs[i].data);
		kr_log_error(PREFILL, "error when computing digest: %s\n",
				kr_strerror(ret));
		return kr_error(ret);
	}
	// Now only check that one of the hashes match.
	bool has_match = false;
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		if (!z_import->digests[i].active)
			continue;
		// hexdump the hash for logging
		char hash_str[digs[i].size * 2 + 1];
		for (ssize_t j = 0; j < digs[i].size; ++j)
			sprintf(hash_str + 2*j, "%02x", digs[i].data[j]);

		if (!z_import->digests[i].expected) {
			kr_log_error(PREFILL, "no ZONEMD found; computed hash: %s\n",
					hash_str);
		} else if (memcmp(z_import->digests[i].expected, digs[i].data,
					digs[i].size) != 0) {
			kr_log_error(PREFILL, "ZONEMD hash mismatch; computed hash: %s\n",
					hash_str);
		} else {
			kr_log_debug(PREFILL, "ZONEMD hash matches\n");
			has_match = true;
			continue;
		}
	}

	for (int i = 0; i < DIGEST_ALG_COUNT; ++i)
		free(digs[i].data);
	bool ok = has_match && (zonemd_is_valid || !z_import->svldr);
	return ok ? kr_ok() : kr_error(ENOENT);
}
#endif


/**
 * @internal Import given rrset to cache.
 *
 * @return error code; we could've chosen to keep importing even if some RRset fails,
 *   but it would be harder to ensure that we don't generate too many logs
 *   and that we pass an error to the finishing callback.
 */
static int zi_rrset_import(trie_val_t *rr_p, void *z_import_v)
{
	zone_import_ctx_t *z_import = z_import_v;
	knot_rrset_t *rr = *rr_p;

	if (rr->type == KNOT_RRTYPE_RRSIG)
		return 0; // we do RRSIGs at once with their types

	const int origin_bailiwick = knot_dname_in_bailiwick(rr->owner, z_import->origin);
	if (unlikely(origin_bailiwick < 0)) {
		KR_DNAME_GET_STR(owner_str, rr->owner);
		kr_log_warning(PREFILL, "ignoring out of bailiwick record(s) on %s\n",
				owner_str);
		return 0; // well, let's continue without error
	}

	// Determine if this RRset is authoritative.
	// We utilize that iteration happens in canonical order.
	bool is_auth;
	const int kdib = knot_dname_in_bailiwick(rr->owner, z_import->last_cut);
	if (kdib == 0 && (rr->type == KNOT_RRTYPE_DS || rr->type == KNOT_RRTYPE_NSEC
				|| rr->type == KNOT_RRTYPE_NSEC3)) {
		// parent side of the zone cut (well, presumably in case of NSEC*)
		is_auth = true;
	} else if (kdib >= 0) {
		// inside non-auth subtree
		is_auth = false;
	} else if (rr->type == KNOT_RRTYPE_NS && origin_bailiwick > 0) {
		// entering non-auth subtree
		z_import->last_cut = rr->owner;
		is_auth = false;
	} else {
		// outside non-auth subtree
		is_auth = true;
		z_import->last_cut = NULL; // so that the next _in_bailiwick() is faster
	}
	// Rare case: `A` exactly on zone cut would be misdetected and fail validation;
	// it's the only type ordered before NS.
	if (unlikely(is_auth && rr->type < KNOT_RRTYPE_NS)) {
		if (rrset_get(z_import->rrsets, rr->owner, KNOT_RRTYPE_NS, 0))
			is_auth = false;
	}

	// Get and validate the corresponding RRSIGs, if authoritative.
	const knot_rrset_t *rrsig = NULL;
	if (is_auth) {
		rrsig = rrset_get(z_import->rrsets, rr->owner, KNOT_RRTYPE_RRSIG, rr->type);
		if (unlikely(!rrsig && z_import->svldr)) {
			KR_DNAME_GET_STR(owner_str, rr->owner);
			KR_RRTYPE_GET_STR(type_str, rr->type);
			kr_log_error(PREFILL, "no records found for %s RRSIG %s\n",
					owner_str, type_str);
			return kr_error(ENOENT);
		}
	}
	if (is_auth && z_import->svldr) {
		int ret = kr_svldr_rrset(rr, &rrsig->rrs, z_import->svldr);
		if (unlikely(ret)) {
			KR_DNAME_GET_STR(owner_str, rr->owner);
			KR_RRTYPE_GET_STR(type_str, rr->type);
			kr_log_error(PREFILL, "validation failed for %s %s: %s\n",
					owner_str, type_str, kr_strerror(ret));
			return kr_error(ret);
		}
	}

	uint8_t rank;
	if (!is_auth) {
		rank = KR_RANK_OMIT;
	} else if (z_import->svldr) {
		rank = KR_RANK_AUTH|KR_RANK_SECURE;
	} else {
		rank = KR_RANK_AUTH|KR_RANK_INSECURE;
	}

	int ret = kr_cache_insert_rr(&the_worker->engine->resolver.cache, rr, rrsig,
					rank, z_import->timestamp_rr,
					// Optim.: only stash NSEC* params at the apex.
					origin_bailiwick == 0);
	if (ret) {
		kr_log_error(PREFILL, "caching an RRset failed: %s\n",
				kr_strerror(ret));
		return kr_error(ret);
	}
	return 0; // success
}

static void ctx_delete(zone_import_ctx_t *z_import)
{
	if (kr_fails_assert(z_import)) return;
	kr_svldr_free_ctx(z_import->svldr);
	mm_ctx_delete(z_import->pool);
}
static void timer_close(uv_handle_t *handle)
{
	ctx_delete(handle->data);
}

/** @internal Iterate over parsed rrsets and try to import each of them. */
static void zi_zone_process(uv_timer_t *timer)
{
	zone_import_ctx_t *z_import = timer->data;

	kr_timer_t stopwatch;
	kr_timer_start(&stopwatch);

	int ret = trie_apply(z_import->rrsets, zi_rrset_import, z_import);
	if (ret == 0) {
		kr_log_info(PREFILL, "performance: validating and caching took %.3lf s\n",
			kr_timer_elapsed(&stopwatch));
	}

	if (z_import->cb)
		z_import->cb(kr_error(ret), z_import->cb_param);
	uv_close((uv_handle_t *)timer, timer_close);
}

/** @internal Store rrset that has been imported to zone import context memory pool.
 * @return -1 if failed; 0 if success. */
static int zi_record_store(zs_scanner_t *s)
{
	if (s->r_data_length > UINT16_MAX) {
		/* Due to knot_rrset_add_rdata(..., const uint16_t size, ...); */
		kr_log_error(PREFILL, "line %"PRIu64": rdata is too long\n",
				s->line_counter);
		return -1;
	}

	if (knot_dname_size(s->r_owner) != strlen((const char *)(s->r_owner)) + 1) {
		kr_log_error(PREFILL, "line %"PRIu64
				": owner name contains zero byte, skip\n",
				s->line_counter);
		return 0;
	}

	zone_import_ctx_t *z_import = (zone_import_ctx_t *)s->process.data;

	knot_rrset_t *new_rr = knot_rrset_new(s->r_owner, s->r_type, s->r_class,
					      s->r_ttl, z_import->pool);
	if (!new_rr) {
		kr_log_error(PREFILL, "line %"PRIu64": error creating rrset\n",
				s->line_counter);
		return -1;
	}
	int res = knot_rrset_add_rdata(new_rr, s->r_data, s->r_data_length,
				       z_import->pool);
	if (res != KNOT_EOK) {
		kr_log_error(PREFILL, "line %"PRIu64": error adding rdata to rrset\n",
				s->line_counter);
		return -1;
	}
	/* zscanner itself does not canonize - neither owner nor insides */
	res = knot_rrset_rr_to_canonical(new_rr);
	if (res != KNOT_EOK) {
		kr_log_error(PREFILL, "line %"PRIu64": error when canonizing: %s\n",
				s->line_counter, knot_strerror(res));
		return -1;
	}

	/* Records in zone file may not be grouped by name and RR type.
	 * Use map to create search key and
	 * avoid ineffective searches across all the imported records. */
	char key_buf[KEY_LEN], *key;
	const int len = key_get(key_buf, new_rr->owner, new_rr->type,
				kr_rrset_type_maysig(new_rr), &key);
	if (len < 0) {
		kr_log_error(PREFILL, "line %"PRIu64": error constructing rrkey\n",
				s->line_counter);
		return -1;
	}
	trie_val_t *rr_p = trie_get_ins(z_import->rrsets, key, len);
	if (!rr_p)
		return -1; // ENOMEM
	if (*rr_p) {
		knot_rrset_t *rr = *rr_p;
		res = knot_rdataset_merge(&rr->rrs, &new_rr->rrs, z_import->pool);
	} else {
		*rr_p = new_rr;
	}
	if (res != 0) {
		kr_log_error(PREFILL, "line %"PRIu64": error saving parsed rrset\n",
				s->line_counter);
		return -1;
	}

	return 0;
}

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
			if (s->r_type == KNOT_RRTYPE_SOA) {
				z_import->origin = knot_dname_copy(s->r_owner,
                                                                   z_import->pool);
			}
			break;
		case ZS_STATE_ERROR:
			kr_log_error(PREFILL, "line: %"PRIu64
				     ": parse error; code: %i ('%s')\n",
				     s->line_counter, s->error.code,
				     zs_strerror(s->error.code));
			return -1;
		case ZS_STATE_INCLUDE:
			kr_log_error(PREFILL, "line: %"PRIu64
				     ": INCLUDE is not supported\n",
				     s->line_counter);
			return -1;
		case ZS_STATE_EOF:
		case ZS_STATE_STOP:
			if (empty) {
				kr_log_error(PREFILL, "empty zone file\n");
				return -1;
			}
			if (!((zone_import_ctx_t *) s->process.data)->origin) {
				kr_log_error(PREFILL, "zone file doesn't contain SOA record\n");
				return -1;
			}
			return (s->error.counter == 0) ? 0 : -1;
		default:
			kr_log_error(PREFILL, "line: %"PRIu64
				     ": unexpected parse state: %i\n",
				     s->line_counter, s->state);
			return -1;
		}
	}

	return -1;
}

int zi_zone_import(const zi_config_t config)
{
	const zi_config_t *c = &config;
	if (kr_fails_assert(c && c->zone_file))
		return kr_error(EINVAL);

	knot_mm_t *pool = mm_ctx_mempool2(1024 * 1024);
	zone_import_ctx_t *z_import = mm_calloc(pool, 1, sizeof(*z_import));
	if (!z_import) return kr_error(ENOMEM);
	z_import->pool = pool;

	z_import->cb = c->cb;
	z_import->cb_param = c->cb_param;
	z_import->rrsets = trie_create(z_import->pool);

	kr_timer_t stopwatch;
	kr_timer_start(&stopwatch);

   //// Parse the whole zone file into z_import->rrsets.
	zs_scanner_t s_storage, *s = &s_storage;
	/* zs_init(), zs_set_input_file(), zs_set_processing() returns -1 in case of error,
	 * so don't print error code as it meaningless. */
	int ret = zs_init(s, c->origin, KNOT_CLASS_IN, c->ttl);
	if (ret != 0) {
		kr_log_error(PREFILL, "error initializing zone scanner instance, error: %i (%s)\n",
			     s->error.code, zs_strerror(s->error.code));
		goto fail;
	}

	ret = zs_set_input_file(s, c->zone_file);
	if (ret != 0) {
		kr_log_error(PREFILL, "error opening zone file `%s`, error: %i (%s)\n",
			     c->zone_file, s->error.code, zs_strerror(s->error.code));
		zs_deinit(s);
		goto fail;
	}

	/* Don't set processing and error callbacks as we don't use automatic parsing.
	 * Parsing as well error processing will be performed in zi_state_parsing().
	 * Store pointer to zone import context for further use. */
	ret = zs_set_processing(s, NULL, NULL, (void *)z_import);
	if (ret != 0) {
		kr_log_error(PREFILL, "zs_set_processing() failed for zone file `%s`, "
				"error: %i (%s)\n",
				c->zone_file, s->error.code, zs_strerror(s->error.code));
		zs_deinit(s);
		goto fail;
	}

	ret = zi_state_parsing(s);
	zs_deinit(s);
	const double time_parse = kr_timer_elapsed(&stopwatch);
	if (ret != 0) {
		kr_log_error(PREFILL, "error parsing zone file `%s`\n", c->zone_file);
		goto fail;
	}
	kr_log_debug(PREFILL, "import started for zone file `%s`\n", c->zone_file);

	KR_DNAME_GET_STR(zone_name_str, z_import->origin);

   //// Choose timestamp_rr, according to config.
	struct timespec now;
	if (clock_gettime(CLOCK_REALTIME, &now)) {
		ret = kr_error(errno);
		kr_log_error(PREFILL, "failed to get current time: %s\n", kr_strerror(ret));
		goto fail;
	}
	if (config.time_src == ZI_STAMP_NOW) {
		z_import->timestamp_rr = now.tv_sec;
	} else if (config.time_src == ZI_STAMP_MTIM) {
		struct stat st;
		if (stat(c->zone_file, &st) != 0) {
			kr_log_debug(PREFILL, "failed to stat file `%s`: %s\n",
					c->zone_file, strerror(errno));
			goto fail;
		}
		z_import->timestamp_rr = st.st_mtime;
	} else {
		ret = kr_error(EINVAL);
		goto fail;
	}
   //// Some sanity checks
	const knot_rrset_t *soa = rrset_get(z_import->rrsets, z_import->origin,
						KNOT_RRTYPE_SOA, 0);
	if (z_import->timestamp_rr > now.tv_sec) {
		kr_log_warning(PREFILL, "zone file `%s` comes from future\n", c->zone_file);
	} else if (!soa) {
		kr_log_warning(PREFILL, "missing %s SOA\n", zone_name_str);
	} else if ((int64_t)z_import->timestamp_rr + soa->ttl < now.tv_sec) {
		kr_log_warning(PREFILL, "%s SOA already expired\n", zone_name_str);
	}

   //// Initialize validator context with the DNSKEY.
	if (c->downgrade)
		goto zonemd;
	struct kr_context *resolver = &the_worker->engine->resolver;
	const knot_rrset_t * const ds = c->ds ? c->ds :
		kr_ta_get(&resolver->trust_anchors, z_import->origin);
	if (!ds) {
		if (!kr_ta_closest(resolver, z_import->origin, KNOT_RRTYPE_DNSKEY))
			goto zonemd; // our TAs say we're insecure
		kr_log_error(PREFILL, "no DS found for `%s`, fail\n", zone_name_str);
		ret = kr_error(ENOENT);
		goto fail;
	}
	if (!knot_dname_is_equal(ds->owner, z_import->origin)) {
		kr_log_error(PREFILL, "mismatching DS owner, fail\n");
		ret = kr_error(EINVAL);
		goto fail;
	}

	knot_rrset_t * const dnskey = rrset_get(z_import->rrsets, z_import->origin,
						KNOT_RRTYPE_DNSKEY, 0);
	if (!dnskey) {
		kr_log_error(PREFILL, "no DNSKEY found for `%s`, fail\n", zone_name_str);
		ret = kr_error(ENOENT);
		goto fail;
	}
	knot_rrset_t * const dnskey_sigs = rrset_get(z_import->rrsets, z_import->origin,
						KNOT_RRTYPE_RRSIG, KNOT_RRTYPE_DNSKEY);
	if (!dnskey_sigs) {
		kr_log_error(PREFILL, "no RRSIGs for DNSKEY found for `%s`, fail\n",
				zone_name_str);
		ret = kr_error(ENOENT);
		goto fail;
	}

	kr_rrset_validation_ctx_t err_ctx;
	z_import->svldr = kr_svldr_new_ctx(ds, dnskey, &dnskey_sigs->rrs,
						z_import->timestamp_rr, &err_ctx);
	if (!z_import->svldr) {
		// log RRSIG stats; very similar to log_bogus_rrsig()
		kr_log_error(PREFILL, "failed to validate DNSKEY for `%s` "
			"(%u matching RRSIGs, %u expired, %u not yet valid, "
			"%u invalid signer, %u invalid label count, %u invalid key, "
			"%u invalid crypto, %u invalid NSEC)\n",
			zone_name_str,
			err_ctx.rrs_counters.matching_name_type,
			err_ctx.rrs_counters.expired, err_ctx.rrs_counters.notyet,
			err_ctx.rrs_counters.signer_invalid,
			err_ctx.rrs_counters.labels_invalid,
			err_ctx.rrs_counters.key_invalid,
			err_ctx.rrs_counters.crypto_invalid,
			err_ctx.rrs_counters.nsec_invalid);
		ret = kr_error(ENOENT);
		goto fail;
	}

   //// Do all ZONEMD processing, if desired.
zonemd: (void)0; // C can't have a variable definition following a label
	double time_zonemd = NAN;
	if (c->zonemd) {
		#if ENABLE_ZONEMD
			kr_timer_start(&stopwatch);
			ret = zonemd_verify(z_import);
			time_zonemd = kr_timer_elapsed(&stopwatch);
		#else
			kr_log_error(PREFILL,
				"ZONEMD check requested but not supported, fail\n");
			ret = kr_error(ENOSYS);
		#endif
	} else {
		ret = kr_ok();
	}
	kr_log_info(PREFILL, "performance: parsing took %.3lf s, hashing took %.3lf s\n",
			time_parse, time_zonemd);
	if (ret) goto fail;

   //// Phase two, after a pause.  Validate and import all the remaining records.
	ret = uv_timer_init(the_worker->loop, &z_import->timer);
	if (ret) goto fail;
	z_import->timer.data = z_import;
	ret = uv_timer_start(&z_import->timer, zi_zone_process, ZONE_IMPORT_PAUSE, 0);
	if (ret) goto fail;

	return kr_ok();
fail:
	if (z_import->cb)
		z_import->cb(kr_error(ret), z_import->cb_param);
	if (kr_fails_assert(ret))
		ret = ENOENT;
	ctx_delete(z_import);
	return kr_error(ret);
}

