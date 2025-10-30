/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/cache/prefetch.h"
#include "lib/cache/top.h"
#include "lib/cache/impl.h"
#include "lib/resolve.h"
#include "daemon/worker.h"

#define VERBOSE_LOG(fmt, ...) kr_log_notice(CACHE, "PREFETCH  " fmt "\n", ## __VA_ARGS__)
#define VERBOSE_LOGp(fmt, ...) { VERBOSE_LOG("%-7s" fmt, log_prefix, ## __VA_ARGS__); log_prefix = ""; }

#define UPDATE_BEFORE_EXP_MAX  5000  // ms
#define FIRST_TIMEOUT          1000  // ms, no prefetch during this time after init; increase?
#define TIMER_PERIOD           1000  // ms


struct sched {
	knot_db_val_t ekey; // RRSet record key (E type)
	uint32_t exp_time;
	uint16_t priority;       // category/load | randomness?
};

uv_timer_t timer_handle;
uv_loop_t *loop_handle = NULL;  // prefetch initialized iff non-NULL
kr_cache_prefetch_callback_t update_callback = NULL;

void timer_callback(uv_timer_t *handle);

knot_db_val_t sched2pkey(struct sched sched) {  /* CACHE_KEY_DEF */
	static uint8_t buf[KR_CACHE_KEY_MAXLEN] = "\0P";  // maybe use a little more than KR_CACHE_KEY_MAXLEN
	knot_db_val_t pkey = { 0 };

	uint8_t *s = buf + 2;

	uint32_t val = sched.exp_time;
	for (size_t i = 0; i < sizeof(val); i++) {
		s[sizeof(val) - i - 1] = 0xFF ^ (val & 0xFF);
		val >>= 8;
	}
	s += sizeof(val);

	*s++ = sched.priority >> 8;
	*s++ = sched.priority & 0xFF;

	// typ 'P' | -(čas vypršení TTL) | priority | původní klíč

	memcpy(s, sched.ekey.data, sched.ekey.len);
	s += sched.ekey.len;

	pkey.data = buf;
	pkey.len = s - buf;
	return pkey;
}

bool pkey2sched(knot_db_val_t pkey, struct sched *sched) {
	static uint8_t buf[KR_CACHE_KEY_MAXLEN];
	uint8_t *s = pkey.data;
	if ((pkey.len < 4 + sizeof(sched->exp_time)) || (*s++ != '\0') || (*s++ != 'P')) return false;

	sched->exp_time = 0;
	for (size_t i = 0; i < sizeof(sched->exp_time); i++) {
		sched->exp_time <<= 8;
		sched->exp_time |= 0xFF ^ *s++;
	}

	sched->priority = (s[0] << 8) | s[1];
	s += 2;

	sched->ekey.len = pkey.len - ((void *)s - pkey.data);
	memcpy(buf, s, sched->ekey.len);
	sched->ekey.data = buf;

	return true;
}

void kr_cache_prefetch_init(uv_loop_t *loop, kr_cache_prefetch_callback_t callback) {
	VERBOSE_LOG("INIT");
	// check already scheduled updates in cache
	uv_timer_init(loop, &timer_handle);
	loop_handle = loop;
	update_callback = callback;
	uv_timer_start(&timer_handle, timer_callback, FIRST_TIMEOUT, TIMER_PERIOD);

	// + possibly configure k, etc.
}

uint16_t kr_cache_prefetch_sched(struct kr_request *req, knot_db_val_t key, struct entry_h *eh) {
	if (!loop_handle) return 0;
	VERBOSE_LOG("SCHED         %6d  %s", eh->ttl, kr_cache_top_strkey(key.data, key.len));
	// check type E; either via kr_gc_key_consistent, or by own method
	// compute load

	// compute whether to prefetch, or return

	struct sched sched = { 0 };
	sched.ekey = key;
	sched.exp_time = eh->time + eh->ttl;
	// compute rest

	knot_db_val_t pkey = sched2pkey(sched);
	cache_op(&req->ctx->cache, write, &pkey, &key, 1);
	cache_op(&req->ctx->cache, commit, true, true);

	return sched.priority; // store in eh (struct entry_h) in api.c:658
}

bool resolve_ekey(knot_db_val_t *ekey) {
	if (!update_callback) return false;
	const uint8_t *ekey_name = ekey->data;
	const uint8_t *ekey_type = ekey->data + ekey->len - 3;
	if ((ekey->len < 4) || (ekey_type[-1] != '\0') || (ekey_type[0] != 'E')) {
		VERBOSE_LOG("    invalid ekey: %d %d %s", ekey_type[-1], ekey_type[0], kr_cache_top_strkey(ekey->data, ekey->len));
		return false;
	}

	knot_dname_t qname[KNOT_DNAME_MAXLEN];
	int qname_len = knot_dname_lf2wire(qname, ekey_type - ekey_name - 1, ekey_name);
	if (qname_len < 0) {
		VERBOSE_LOG("    cannot convert to qname");
		return false;
	}

	uint16_t qtype = 0;
	memcpy(&qtype, ekey_type + 1, 2);  // can be returned from kr_gc_key_consistent

	VERBOSE_LOG("UPDATE  %s %d", kr_cache_top_strkey(qname, qname_len), qtype);
	int ret = update_callback(qname, qtype);
	return !ret;
}

void timer_callback(uv_timer_t *handle) {
	char *log_prefix = "TIMER";

	struct timeval tv;
	if (gettimeofday(&tv, NULL)) return;
	uint32_t time_now = tv.tv_sec;

	for (int i = 0; i < 100; i++) {
		knot_db_val_t key = { .data = "\0Q", .len = 2 };  // a key just after last P-record
		knot_db_val_t val = { 0 };

		if (cache_op(&the_resolver->cache, read_leq, &key, &val) <= 0) {   // read less seems not to work
			VERBOSE_LOGp("nothing found");
			goto done;
		}

		struct sched sched = { 0 };
		if (!pkey2sched(key, &sched)) {
			VERBOSE_LOGp("found but not relevant: %s", kr_cache_top_strkey(key.data, key.len));
			goto done;
		}
		int32_t ttl = sched.exp_time - time_now;
		if (ttl > UPDATE_BEFORE_EXP_MAX / 1000) {
			VERBOSE_LOGp("next:  %6d %s", sched.exp_time - time_now, kr_cache_top_strkey(key.data, key.len));
			goto done;
		}
		VERBOSE_LOGp("found: %6d %s", ttl, kr_cache_top_strkey(key.data, key.len));

		int ret = cache_op(&the_resolver->cache, remove, &key, 1);
		if (ret == 0) {
			VERBOSE_LOGp("already removed");
			continue;
		}
		if (ret < 0) {
			VERBOSE_LOGp("cannot remove");
			goto done; // some error?
		}
		if (cache_op(&the_resolver->cache, commit, true, true) != 0) {
			VERBOSE_LOGp("cannot commit");
			goto done; // some error?
		}

		if (ttl < 0) {
			VERBOSE_LOGp("skipping expired");
			continue;
		}

		// verify ekey existence + ttl

		resolve_ekey(&sched.ekey);
		break;
	}

	uv_timer_start(&timer_handle, timer_callback, 0, TIMER_PERIOD);  // continue on next libuv cycle instead of waiting 1s
done:
	cache_op(&the_resolver->cache, commit, false, true);
}
