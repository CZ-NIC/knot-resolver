/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/cache/prefetch.h"
#include "lib/cache/top.h"
#include "lib/cache/impl.h"
#include "lib/resolve.h"
#include "daemon/worker.h"

#include <math.h>

#define VERBOSE_LOG(fmt, ...) kr_log_notice(CACHE, "PREFETCH  " fmt "\n", ## __VA_ARGS__)
#define VERBOSE_LOG_pkey(fmt, ...) VERBOSE_LOG(fmt " %6d %s", ## __VA_ARGS__, ttl, kr_cache_top_strkey(pkey.data, pkey.len))

#define FIRST_TIMEOUT_MS           2000  // ms, no prefetch during this time after init
#define UPDATE_BEFORE_EXP_S        5     // s
#define STRICTER_BEFORE_EXP_MS     2000  // ms, start increasing the bounds this time before expiration
#define MIN_ACCESSES_AT_EXP        5243  // acc., 5s access period

struct sched {
	knot_db_val_t ekey; // RRSet record key (E type)
	uint32_t exp_time;
	uint16_t rrtype;    // the original type (incl. DNAME/CNAME)
	uint8_t priority;   // accesses normalized to 1B for normal-size records
};

uv_timer_t timer_handle;
uv_loop_t *loop_handle = NULL;  // prefetch initialized iff non-NULL
kr_cache_prefetch_callback_t update_callback = NULL;
float conf_min_accesses_per_update;
float conf_min_accesses_by_period;
bool conf_enabled = false;

void timer_callback(uv_timer_t *handle);

knot_db_val_t sched2pkey(struct sched sched)
{
	// CACHE_KEY_DEF:  type 'P', -(time of expiration), priority, original E-type key with type replaced by original rrtype
	static uint8_t buf[KR_CACHE_KEY_MAXLEN + 7] = "\0P";
	knot_db_val_t pkey = { 0 };

	uint8_t *s = buf + 2;

	uint32_t val = sched.exp_time;
	for (size_t i = 0; i < sizeof(val); i++) {
		s[sizeof(val) - i - 1] = 0xFF ^ (val & 0xFF);
		val >>= 8;
	}
	s += sizeof(val);

	*s++ = sched.priority;

	memcpy(s, sched.ekey.data, sched.ekey.len - 2);
	s += sched.ekey.len;
	memcpy(s - 2, &sched.rrtype, 2);  // use rrtype instead of key type

	pkey.data = buf;
	pkey.len = s - buf;
	return pkey;
}

bool pkey2sched(knot_db_val_t pkey, struct sched *sched)
{
	static uint8_t buf[KR_CACHE_KEY_MAXLEN];
	uint8_t *s = pkey.data;
	if ((pkey.len < 4 + sizeof(sched->exp_time)) || (*s++ != '\0') || (*s++ != 'P')) return false;

	sched->exp_time = 0;
	for (size_t i = 0; i < sizeof(sched->exp_time); i++) {
		sched->exp_time <<= 8;
		sched->exp_time |= 0xFF ^ *s++;
	}

	sched->priority = *s++;

	sched->ekey.len = pkey.len - ((void *)s - pkey.data);
	memcpy(buf, s, sched->ekey.len);
	sched->ekey.data = buf;
	memcpy(&sched->rrtype, sched->ekey.data + sched->ekey.len - 2, 2);

	// replace rrtype with key type in ekey
	if ((sched->rrtype == KNOT_RRTYPE_CNAME) || (sched->rrtype == KNOT_RRTYPE_DNAME)) {
		const uint16_t type = KNOT_RRTYPE_NS;
		memcpy(sched->ekey.data + sched->ekey.len - 2, &type, 2);
	}

	return true;
}

bool kr_cache_prefetch_parse_pkey(knot_db_val_t pkey, knot_db_val_t *ekey, uint32_t *exp_time)
{
	struct sched sched = { 0 };
	bool ret = pkey2sched(pkey, &sched);
	*ekey = sched.ekey;
	*exp_time = sched.exp_time;
	return ret;
}


void kr_cache_prefetch_callback_init(uv_loop_t *loop, kr_cache_prefetch_callback_t callback)
{
	uv_timer_init(loop, &timer_handle);
	loop_handle = loop;
	update_callback = callback;
}

void kr_cache_prefetch_init(uint32_t max_access_period_sec, float min_accesses_per_update)
{
	if (!loop_handle) return;
	uv_timer_start(&timer_handle, timer_callback, FIRST_TIMEOUT_MS, 0);
	conf_min_accesses_per_update = min_accesses_per_update;
	conf_min_accesses_by_period = 1 / (1 - kr_cache_top_decay_mult(&the_resolver->cache.top, max_access_period_sec));
	conf_enabled = true;
}

void kr_cache_prefetch_sched(knot_db_val_t key, struct entry_h *eh, size_t eh_len, size_t whole_entry_len, uint16_t rrtype)
{
	if (!conf_enabled) return;
	struct kr_cache *cache = &the_resolver->cache;
	const int ktype = key_consistent(key);
	if (ktype & ~0xFFFF) return;  // not E-type key

	const int32_t time_to_update = eh->ttl - UPDATE_BEFORE_EXP_S;
	if (time_to_update < 1) return;  // too small TTL

	const uint16_t load = kr_cache_top_load(&cache->top, key.data, key.len);
	size_t keydata_len = kr_cache_top_entry_size(key.len, whole_entry_len);
	const float price16 = 0x1p-16 * kr_cache_top_entry_price(&cache->top, keydata_len);

	/*
	 * Condition on minimal accesses per update:
	 *   accesses * (1 - decay_mult(time_to_update))     >  MIN_ACCESSES_PER_UPDATE
	 * Condition on maximal period:
	 *   accesses * (1 - decay_mult(MAX_ACCESS_PERIOD))  >  1
	 *
	 * Accesses to load:
	 *   load = accesses * price(keydata_len) / (1 << 16)
	 *
	 * Load to accesses (but avoid rounding):
	 *   accesses = load / (price(keydata_len) >> 16)
	 *
	 * Conditions rewritten as load bound:
	 *   load > (price(keydata_len >> 16) / (1 - decay_mult(time_to_update)) * MIN_ACCESSES_PER_UPDATE
	 *   load > (price(keydata_len >> 16) / (1 - decay_mult(MAX_ACCESS_PERIOD))
	 *
	 * Defining config-dependent constant and rewriting:
	 *   MIN_ACCESSES_BY_PERIOD = 1 / (1 - decay_mult(MAX_ACCESS_PERIOD))
	 *   load > (price(keydata_len) >> 16) * max(MIN_ACCESSES_BY_PERIOD, MIN_ACCESSES_PER_UPDATE / (1 - decay_mult(time_to_update)))
	 *
	 */

	const float min_accesses_by_per_update = conf_min_accesses_per_update / (1 - kr_cache_top_decay_mult(&cache->top, time_to_update));
	const float min_loadf = price16 * MAX(conf_min_accesses_by_period, min_accesses_by_per_update);
	const uint16_t min_load = MIN(min_loadf, 0xFFFF);

	if (load < min_load) return;  // under threshold

	const double accesses = (double)load / price16; // includes the just occurring write access

	struct sched sched = { 0 };
	sched.ekey = key;
	sched.rrtype = rrtype;
	sched.exp_time = eh->time + eh->ttl;
	sched.priority = MIN(sqrt(accesses * /* top base price */ 5) + 1, 255);
		// accesses distributed in range of 1B for normal-size records (non-zero, capped for larger)

	knot_db_val_t pkey = sched2pkey(sched);

	const int32_t ttl = eh->ttl;
	VERBOSE_LOG_pkey("scheduling      %7.1f > %-7.1f",
		load / price16, min_load / price16);

	if (KNOT_RRTYPE_NS) {
		keydata_len = (keydata_len - whole_entry_len) / 3 + eh_len;   // we divide size of common data of NS, CNAME, DNAME between them
	}
	struct entry_p ep = {
		.ekeydata_len = (keydata_len > 0xFFFF ? 0xFFFF : keydata_len),
		.min_load = min_load
	};
	knot_db_val_t data = { .data = &ep, .len = sizeof(ep) };
	cache_op(cache, write, &pkey, &data, 1);

	eh->prefetch_priority = sched.priority;

	// to be called during another write transaction, so we are not committing here
}

void kr_cache_prefetch_unsched(knot_db_val_t key, const struct entry_h *eh, uint16_t rrtype)
{
	if (!conf_enabled || !eh || !eh->prefetch_priority) return;
	struct sched sched = {
		.ekey = key,
		.rrtype = rrtype,
		.exp_time = eh->time + eh->ttl,
		.priority = eh->prefetch_priority,
	};
	knot_db_val_t pkey = sched2pkey(sched);
	cache_op(&the_resolver->cache, remove, &pkey, 1);
}

bool resolve_ekey(knot_db_val_t *ekey, uint16_t rrtype)
{
	if (!update_callback) return false;
	if (key_consistent(*ekey) & ~0xFFFF) {  // E-type key
		VERBOSE_LOG("    invalid ekey: %s", kr_cache_top_strkey(ekey->data, ekey->len));
		return false;
	}

	knot_dname_t qname[KNOT_DNAME_MAXLEN];
	int qname_len = knot_dname_lf2wire(qname, ekey->len - 4, ekey->data);
	if (qname_len < 0) {
		VERBOSE_LOG("    cannot convert to qname");
		return false;
	}

	int ret = update_callback(qname, rrtype);
	return !ret;
}

bool defer_busy = false;
bool timer_skipped = false;
bool timer_first_in_sec = false;

void timer_callback(uv_timer_t *handle)
{
	static int race_delay = 0;  // timer delay arising from detected race conditions on P entry removals

	if (defer_busy) {
		timer_skipped = true;
		VERBOSE_LOG("skipped, defer busy");
		return;
	}

	struct timeval tv;
	if (gettimeofday(&tv, NULL)) return;
	uint32_t time_now = tv.tv_sec;
	uint64_t time_now_msec = tv.tv_usec / 1000;

	for (int i = 0; i < 100; i++) {
		knot_db_val_t pkey = { .data = "\0Q", .len = 2 };  // a key just after last P-record
		knot_db_val_t val = { 0 };

		// find the next P-entry for update
		if (cache_op(&the_resolver->cache, read_leq, &pkey, &val) <= 0) goto done;  // nothing found

		struct sched sched = { 0 };
		if (!pkey2sched(pkey, &sched)) goto done;  // not a P-entry

		const int32_t ttl = sched.exp_time - time_now;
		if (ttl > UPDATE_BEFORE_EXP_S) {
			static int32_t next_time_logged = 0;
			if (next_time_logged != sched.exp_time) {
				VERBOSE_LOG_pkey("next                             ");
				next_time_logged = sched.exp_time;
			}
			goto done;  // found but for later update
		}

		uint16_t min_load = 0xFFFF;
		if (val.len == sizeof(struct entry_p)) {
			min_load = ((struct entry_p *)val.data)->min_load;
		}

		// remove the found P-entry; it might fail due to a race but only in the 1st iteration
		int ret = cache_op(&the_resolver->cache, remove, &pkey, 1);
		if (ret == 0) {
			if (timer_first_in_sec) {
				// mitigate race probability with the same process again
				race_delay = (race_delay + 37) % 100;
				timer_first_in_sec = false;
				VERBOSE_LOG_pkey("found but race detected, delaying");
			} else {
				VERBOSE_LOG_pkey("found but race detected          ");
			}
			// write transaction is now kept open for all following iterations,
			// so remove will not fail here again
			continue;
		}
		if (ret < 0) {
			VERBOSE_LOG_pkey("found but cannot remove          ");
			goto done; // some error?
		}

		if (min_load == 0xFFFF) {
			VERBOSE_LOG_pkey("found but invalid data           ");
			continue;
		}

		if (ttl < 0) {
			VERBOSE_LOG_pkey("found expired                    ");
			continue;
		}

		// check E-key existence
		ret = cache_op(&the_resolver->cache, read, &sched.ekey, &val, 1);
		if (ret != 0) {
			VERBOSE_LOG_pkey("found but no E-key               ");
			continue;
		}

		// make min_load more strict closer to expiration
		const int64_t ttl_msec = 1000 * ttl + (1000 - time_now_msec);
			// with zero TTL, the record is considered valid till the end of the current second
		const size_t keydata_len = kr_cache_top_entry_size(sched.ekey.len, val.len);
		const float price16 = 0x1p-16 * kr_cache_top_entry_price(&the_resolver->cache.top, keydata_len);
		if (ttl_msec < STRICTER_BEFORE_EXP_MS) {
			const float stricter_min_load =
				(MIN_ACCESSES_AT_EXP -
					(MIN_ACCESSES_AT_EXP - conf_min_accesses_by_period) * ttl_msec / STRICTER_BEFORE_EXP_MS
				) * price16;
			min_load = MAX(min_load, MIN(stricter_min_load, 0xFFFF));
		}

		// check whether still eligible for prefetch by current load
		const uint16_t load = kr_cache_top_load(&the_resolver->cache.top, sched.ekey.data, sched.ekey.len);
		if (load < min_load) {
			VERBOSE_LOG_pkey("found non-elig. %7.1f < %-7.1f",
					load / price16, min_load / price16);
			continue;
		}

		// check that E-key data matches P-entry (no update occurred in meantime)
		ret = entry_h_seek(&val, sched.rrtype);
		if (ret != 0) {
			VERBOSE_LOG_pkey("found but invalid E-key data     ");
			continue;
		}

		struct entry_h *eh = entry_h_consistent_E(val, sched.rrtype);
		if (!eh) {
			VERBOSE_LOG_pkey("found but invalid E-key eh data  ");
			continue;
		}

		if ((eh->time + eh->ttl != sched.exp_time) || (eh->prefetch_priority != sched.priority)) {
			VERBOSE_LOG_pkey("found but already updated        ");
			continue;
		}

		// close write transaction and initiate update
		if (cache_op(&the_resolver->cache, commit, true, true) != 0) {
			VERBOSE_LOG_pkey("found but cannot commit removal  ");
			goto done; // some error?
		}

		VERBOSE_LOG_pkey("updating        %7.1f > %-7.1f",
				load / price16, min_load / price16);
		resolve_ekey(&sched.ekey, sched.rrtype);
		break;
	}

	// other P-entries for update in this sec might exist, continue in next libuv cycle
	cache_op(&the_resolver->cache, commit, true, true);
	uv_timer_start(&timer_handle, timer_callback, 0, 0);
	timer_first_in_sec = false;
	return;

done:
	// no other P-entries for update in this sec exist, continue sometime in the first 100 ms of the next sec
	cache_op(&the_resolver->cache, commit, true, true);
	uint64_t timeout = 1000 - time_now_msec + (race_delay + time_now * 13) % 100;
	uv_timer_start(&timer_handle, timer_callback, timeout, 0);
	timer_first_in_sec = true;
}

void kr_cache_prefetch_defer_busy(bool busy)
{
	defer_busy = busy;

	if (!defer_busy && timer_skipped) {
		// continue with updates in next libuv cycle
		uv_timer_start(&timer_handle, timer_callback, 0, 0);
		timer_first_in_sec = false;
		timer_skipped = false;
	}
}
