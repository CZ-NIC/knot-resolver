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

#define UPDATE_BEFORE_EXP_S        5     // s
#define FIRST_TIMEOUT_MS           1000  // ms, no prefetch during this time after init; increase?
#define TIMER_PERIOD_MS            1000  // ms

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

knot_db_val_t sched2pkey(struct sched sched) {
	// CACHE_KEY_DEF:  type 'P', -(time of expiration), priority, original E-type key with type replaced by original rrtype
	static uint8_t buf[KR_CACHE_KEY_MAXLEN] = "\0P";  // maybe use a little more than KR_CACHE_KEY_MAXLEN
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

bool pkey2sched(knot_db_val_t pkey, struct sched *sched) {
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

void kr_cache_prefetch_parse_pkey(knot_db_val_t pkey, knot_db_val_t *ekey, uint32_t *exp_time) {
	struct sched sched = { 0 };
	pkey2sched(pkey, &sched);  // XXX false?
	*ekey = sched.ekey;
	*exp_time = sched.exp_time;
	// TODO  efficiency?
}


void kr_cache_prefetch_callback_init(uv_loop_t *loop, kr_cache_prefetch_callback_t callback) {
	VERBOSE_LOG("INIT callback");
	uv_timer_init(loop, &timer_handle);
	loop_handle = loop;
	update_callback = callback;
}

void kr_cache_prefetch_init(uint32_t max_access_period_sec, float min_accesses_per_update) {
	if (!loop_handle) return;
	VERBOSE_LOG("INIT settings (min_accesses_per_update = %f, max_access_period = %u s)",
			min_accesses_per_update, max_access_period_sec);
	uv_timer_start(&timer_handle, timer_callback, FIRST_TIMEOUT_MS, TIMER_PERIOD_MS);
	conf_min_accesses_per_update = min_accesses_per_update; // TODO use config
	conf_min_accesses_by_period = 1 / (1 - kr_cache_top_decay_mult(&the_resolver->cache.top, max_access_period_sec));
	conf_enabled = true;
}

void kr_cache_prefetch_sched(knot_db_val_t key, struct entry_h *eh, size_t eh_len, size_t whole_entry_len, uint16_t rrtype) {
	if (!conf_enabled) return;
	struct kr_cache *cache = &the_resolver->cache;
	VERBOSE_LOG("SCHED         %6d  %s", eh->ttl, kr_cache_top_strkey(key.data, key.len));
	const int ktype = key_consistent(key);
	if (ktype & ~0xFFFF) {
		VERBOSE_LOG("    not E-type key");
		return;
	}

	const int32_t time_to_update = eh->ttl - UPDATE_BEFORE_EXP_S;
	if (time_to_update < 1) return;

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

	VERBOSE_LOG("    load: %u (%0.2f acc.), min_load: %u (%0.2f acc.), to_update: %d, size: %zu",
		load, load / price16,
		min_load, min_load / price16,
		eh->ttl - UPDATE_BEFORE_EXP_S,
		keydata_len);

	if (load < min_load) {
		VERBOSE_LOG("    under threshold");
		return;
	}

	const double accesses = (double)load / price16; // includes the just occurring write access

	struct sched sched = { 0 };
	sched.ekey = key;
	sched.rrtype = rrtype;
	sched.exp_time = eh->time + eh->ttl;
	sched.priority = MIN(sqrt(accesses * /* top base price */ 5) + 1, 255);  // TODO  consider this vs lin-log gc categories
		// accesses distributed in range of 1B for normal-size records (non-zero, capped for larger)

	knot_db_val_t pkey = sched2pkey(sched);
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

void kr_cache_prefetch_unsched(knot_db_val_t key, const struct entry_h *eh, uint16_t rrtype) {
	if (!conf_enabled || !eh || !eh->prefetch_priority) return;
	VERBOSE_LOG("UNSCHED               %s", kr_cache_top_strkey(key.data, key.len));
	struct sched sched = {
		.ekey = key,
		.rrtype = rrtype,
		.exp_time = eh->time + eh->ttl,
		.priority = eh->prefetch_priority,
	};
	knot_db_val_t pkey = sched2pkey(sched);
	cache_op(&the_resolver->cache, remove, &pkey, 1);
}

bool resolve_ekey(knot_db_val_t *ekey, uint16_t rrtype) {
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

	VERBOSE_LOG("UPDATE  %s %d", kr_cache_top_strkey(qname, qname_len), rrtype);
	int ret = update_callback(qname, rrtype);
	return !ret;
}

bool defer_busy = false;
bool timer_skipped = false;

void timer_callback(uv_timer_t *handle) {
	char *log_prefix = "TIMER";

	if (defer_busy) {
		timer_skipped = true;
		VERBOSE_LOGp("skipped, defer busy");
		return;
	}

	struct timeval tv;
	if (gettimeofday(&tv, NULL)) return;
	uint32_t time_now = tv.tv_sec;

	for (int i = 0; i < 100; i++) {
		knot_db_val_t pkey = { .data = "\0Q", .len = 2 };  // a key just after last P-record
		knot_db_val_t val = { 0 };

		if (cache_op(&the_resolver->cache, read_leq, &pkey, &val) <= 0) {   // read_less seems not to work
			VERBOSE_LOGp("nothing found");
			goto done;
		}

		struct sched sched = { 0 };
		if (!pkey2sched(pkey, &sched)) {
			VERBOSE_LOGp("found but not relevant: %s", kr_cache_top_strkey(pkey.data, pkey.len));
			goto done;
		}
		int32_t ttl = sched.exp_time - time_now;
		if (ttl > UPDATE_BEFORE_EXP_S) {
			VERBOSE_LOGp("next:  %6d %s", sched.exp_time - time_now, kr_cache_top_strkey(pkey.data, pkey.len));
			goto done;
		}
		VERBOSE_LOGp("found: %6d %s", ttl, kr_cache_top_strkey(pkey.data, pkey.len));

		uint16_t min_load = 0xFFFF;
		if (val.len == sizeof(struct entry_p)) {
			min_load = ((struct entry_p *)val.data)->min_load;
		} else VERBOSE_LOGp("invalid data size");

		int ret = cache_op(&the_resolver->cache, remove, &pkey, 1);
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

		const uint16_t load = kr_cache_top_load(&the_resolver->cache.top, sched.ekey.data, sched.ekey.len);
		if (load < min_load) {
			VERBOSE_LOGp("skipping, no longer eligible for prefetch (%d < %d)", load, min_load);
			continue;
		}

		ret = cache_op(&the_resolver->cache, read, &sched.ekey, &val, 1);
		if (ret != 0) {
			VERBOSE_LOGp("ekey not found in cache");
			continue;
		}

		ret = entry_h_seek(&val, sched.rrtype);
		if (ret != 0) {
			VERBOSE_LOGp("invalid data for ekey");
			continue;
		}

		struct entry_h *eh = entry_h_consistent_E(val, sched.rrtype);
		if (!eh) {
			VERBOSE_LOGp("invalid data for ekey");
			continue;
		}

		if ((eh->time + eh->ttl != sched.exp_time) || (eh->prefetch_priority != sched.priority)) {
			VERBOSE_LOGp("ttl/priority mismatch, maybe already updated (ttl %d -> %d, prio. %d -> %d", 
					sched.exp_time - time_now,
					eh->time + eh->ttl - time_now,
					sched.priority,
					eh->prefetch_priority);
			continue;
		}

		resolve_ekey(&sched.ekey, sched.rrtype);
		break;
	}

	uv_timer_start(&timer_handle, timer_callback, 0, TIMER_PERIOD_MS);  // continue on next libuv cycle instead of waiting 1s
done:
	cache_op(&the_resolver->cache, commit, false, true);
}

void kr_cache_prefetch_defer_busy(bool busy) {
	defer_busy = busy;

	if (!defer_busy && timer_skipped) {
		uv_timer_start(&timer_handle, timer_callback, 0, TIMER_PERIOD_MS);  // continue on next libuv cycle
		timer_skipped = false;
	}
}
