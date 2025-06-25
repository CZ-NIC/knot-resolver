/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <limits.h>
#include "lib/utils.h"
#include "lib/defines.h"
#include "lib/cache/top.h"
#include "lib/cache/impl.h"
#include "lib/mmapped.h"
#include "lib/kru.h"

// #ifdef LOG_GRP_MDB
#define VERBOSE_LOG(...) printf("GC KRU " __VA_ARGS__)

#define FILE_FORMAT_VERSION 1  // fail if different

#define TICK_SEC     1
#define NORMAL_SIZE  150 // B; normal size of cache entry
#define BASE_PRICE   (((kru_price_t)5) << (KRU_PRICE_BITS - 16))
	// for cache entries of NORMAL_SIZE
	// -> normal increment: 5 (16-bit)
	// -> instant limit:   ~(2^16 / 5)
#define MAX_DECAY    (BASE_PRICE / 2)  // per sec
	// -> rate limit: 1/2 per sec  (more frequent accesses are incomparable)
	// -> half-life:  ~5h 3min


static inline uint32_t ticks_now(void)
{
	struct timespec now_ts = {0};
	int ret = clock_gettime(
		#ifdef CLOCK_REALTIME_COARSE // fails on macOS; docs say it's Linux-specific
			CLOCK_REALTIME_COARSE,
		#else
			CLOCK_REALTIME,
		#endif
		&now_ts);
	kr_assert(ret == 0);
	return now_ts.tv_sec / TICK_SEC;
}

static inline bool first_access_ro(struct kr_cache_top_context *ctx, kru_hash_t hash) {
	// struct kr_cache_top_context { uint64_t bloom[4]; }
	static_assert(sizeof(((struct kr_cache_top_context *)0)->bloom[0]) * 8 == 32);
	static_assert(sizeof(((struct kr_cache_top_context *)0)->bloom)    * 8 == 32 * 16);
		// expected around 40 unique cache accesses per request context, up to ~100;
		// prob. of collision of 40th unique access with the preceeding ones: ~0.5 %;
		// 60th: ~1.9 %; 80th: 4.5 %; 100th: 8.4 %; 150th: 22 %; 200th; 39 %
		//   -> collision means not counting the cache access in KRU while it should be

	uint8_t *h = (uint8_t *)&hash;
	static_assert(sizeof(kru_hash_t) >= 8);

	bool accessed = 1u &
		(ctx->bloom[h[0] % 16] >> (h[1] % 32)) &
		(ctx->bloom[h[2] % 16] >> (h[3] % 32)) &
		(ctx->bloom[h[4] % 16] >> (h[5] % 32)) &
		(ctx->bloom[h[6] % 16] >> (h[7] % 32));

	return !accessed;
}

static inline bool first_access(struct kr_cache_top_context *ctx, kru_hash_t hash) {
	if (!first_access_ro(ctx, hash)) return false;

	uint8_t *h = (uint8_t *)&hash;
	static_assert(sizeof(kru_hash_t) >= 8);

	{ // temporal statistics, TODO remove
		int ones = 0;
		for (int i = 0; i < 16; i++) {
			ones += __builtin_popcount(ctx->bloom[i]);
		}
		double collision_prob = ones / 512.0; // 1-bit collision
		collision_prob *= collision_prob;     // 2-bit collision
		collision_prob *= collision_prob;     // 4-bit collision

		if (collision_prob > 0.1) {
			VERBOSE_LOG("BLOOM %d unique accesses, collision prob. %5.3f %% (%d/512 ones)\n", ctx->cnt, 100.0 * collision_prob, ones);
		}
		ctx->cnt++;
	}

	ctx->bloom[h[0] % 16] |= 1u << (h[1] % 32);
	ctx->bloom[h[2] % 16] |= 1u << (h[3] % 32);
	ctx->bloom[h[4] % 16] |= 1u << (h[5] % 32);
	ctx->bloom[h[6] % 16] |= 1u << (h[7] % 32);

	kr_assert(!first_access_ro(ctx, hash));

	return true;
}


int kr_cache_top_init(struct kr_cache_top *top, char *mmap_file, size_t cache_size) {
	size_t size = 0, capacity_log = 0;
	VERBOSE_LOG("INIT, cache size %d\n", cache_size);

	if (cache_size > 0) {
		const size_t capacity = 2<<19;  // TODO calculate from cache_size
		for (size_t c = capacity - 1; c > 0; c >>= 1) capacity_log++;

		size = offsetof(struct top_data, kru) + KRU.get_size(capacity_log);
	} // else use existing file settings

	struct top_data header = {
		.version          = (FILE_FORMAT_VERSION << 1) | kru_using_avx2(),
		.base_price_norm  = BASE_PRICE * NORMAL_SIZE,
		.max_decay        = MAX_DECAY
	};

	size_t header_size = offsetof(struct top_data, max_decay) + sizeof(header.max_decay);
	static_assert(  // no padding up to .max_decay
		offsetof(struct top_data, max_decay) ==
			sizeof(header.version) +
			sizeof(header.base_price_norm),
		"detected padding with undefined data inside mmapped header");

	if (cache_size == 0) {
		header_size = offsetof(struct top_data, base_price_norm);
	}

	VERBOSE_LOG("INIT mmapped_init\n");
	int state = mmapped_init(&top->mmapped, mmap_file, size, &header, header_size, true);
	top->data = top->mmapped.mem;
	bool using_existing = false;

	// try using existing data
	if ((state >= 0) && (state & MMAPPED_EXISTING)) {
		if (!KRU.check_size((struct kru *)top->data->kru, top->mmapped.size - offsetof(struct top_data, kru))) {
			VERBOSE_LOG("INIT reset, wrong size\n");
			state = mmapped_init_reset(&top->mmapped, mmap_file, size, &header, header_size);
			top->data = top->mmapped.mem;
		} else {
			using_existing = true;
			VERBOSE_LOG("INIT finish existing\n");
			state = mmapped_init_finish(&top->mmapped);
		}
	}

	// initialize new instance
	if ((state >= 0) && !(state & MMAPPED_EXISTING) && (state & MMAPPED_PENDING)) {
		bool succ = KRU.initialize((struct kru *)top->data->kru, capacity_log, top->data->max_decay);
		if (!succ) {
			state = kr_error(EINVAL);
			goto fail;
		}
		kr_assert(KRU.check_size((struct kru *)top->data->kru, top->mmapped.size - offsetof(struct top_data, kru)));

		VERBOSE_LOG("INIT finish new\n");
		state = mmapped_init_finish(&top->mmapped);
	}

	if (state < 0) goto fail;
	kr_assert(state == 0);

	top->ctx = NULL;
	kr_log_info(CACHE, "Cache top initialized %s (%s).\n",
			using_existing ? "using existing data" : "as empty",
			(kru_using_avx2() ? "AVX2" : "generic"));
	return 0;

fail:
	VERBOSE_LOG("INIT error, deinit\n");
	kr_cache_top_deinit(top);
	kr_log_crit(SYSTEM, "Initialization of cache top failed.\n");
	return state;
}

void kr_cache_top_deinit(struct kr_cache_top *top) {
	top->data = NULL;
	mmapped_deinit(&top->mmapped);
}

/* text mode: '\0' -> '|'
 * hex bytes: <x00010203x>
 * decimal bytes: <0.1.2.3>
 */
char *kr_cache_top_strkey(void *key, size_t len) {
	static char str[4 * KR_CACHE_KEY_MAXLEN + 1];
	if (4 * len + 1 > sizeof(str)) len = (sizeof(str) - 1) / 4;
	unsigned char *k = key;

	bool bytes_mode = false;
	bool decimal_bytes = false;
	int force_bytes = 0;
	char *strp = str;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = k[i];
		if ((force_bytes-- <= 0) &&
				((c == 0) || ((c > ' ') && (c <= '~') && (c != '|') && (c != '<') && (c != '>')))) {
			//if (c == ' ') c = '_';
			if (c == 0)   c = '|';
			if (bytes_mode) {
				if (decimal_bytes) strp--;
				*strp++ = '>';
				bytes_mode = false;
				decimal_bytes = false;
			}
			*strp++ = c;
			if ((i > 0) && (k[i - 1] == '\0') && ((i == 1) || k[i - 2] == '\0')) {
				switch (k[i]) {
					case 'S':
						if (len == 6) decimal_bytes = true;
						// pass through
					case '3':
						force_bytes = INT_MAX;
						break;
					case 'E':
						force_bytes = true;
						decimal_bytes = true;
						break;
				}
			}
		} else {
			if (!bytes_mode) {
				*strp++ = '<';
				if (!decimal_bytes) *strp++ = 'x';
				bytes_mode = true;
			}
			if (decimal_bytes) {
				if (c >= 100) *strp++ = '0' + c / 100;
				if (c >= 10)  *strp++ = '0' + c / 10 % 10;
				*strp++ = '0' + c % 10;
				*strp++ = '.';
			} else {
				*strp++ = "0123456789ABCDEF"[c >> 4];
				*strp++ = "0123456789ABCDEF"[c & 15];
			}
		}
	}
	if (bytes_mode) {
		if (decimal_bytes) {
			strp--;
		} else {
			*strp++ = 'x';
		}
		*strp++ = '>';
		bytes_mode = false;
	}
	*strp++ = '\0';
	return str;
}

void kr_cache_top_access(struct kr_cache_top *top, void *key, size_t key_len, size_t data_size, char *debug_label)
{
	kru_hash_t hash = KRU.hash_bytes((struct kru *)&top->data->kru, (uint8_t *)key, key_len);
	const bool unique = top->ctx ? first_access(top->ctx, hash) : true;
	const size_t size = kr_cache_top_entry_size(key_len, data_size);
	if (unique) {
		const kru_price_t price = kr_cache_top_entry_price(top, size);
		KRU.load_hash((struct kru *)&top->data->kru, ticks_now(), hash, price);
	}
	VERBOSE_LOG("ACCESS %-19s%4d B %-5s  %s\n", debug_label, size,
			!top->ctx ? "NO_CTX" : unique ? "" : "SKIP",
			kr_cache_top_strkey(key, key_len));
}

// temporal logging one level under _access
void kr_cache_top_access_cdb(struct kr_cache_top *top, void *key, size_t len, char *debug_label)
{

	// VERBOSE_LOG("ACCESS   %-17s %s\n", debug_label, kr_cache_top_strkey(key, len));
}

struct kr_cache_top_context *kr_cache_top_context_switch(struct kr_cache_top *top,
		struct kr_cache_top_context *new_ctx, char *debug_label)
{
	struct kr_cache_top_context *old_ctx = top->ctx;
	top->ctx = new_ctx;
	return old_ctx;
}

uint16_t kr_cache_top_load(struct kr_cache_top *top, void *key, size_t len) {
	kru_hash_t hash = KRU.hash_bytes((struct kru *)&top->data->kru, (uint8_t *)key, len);
	uint16_t load = KRU.load_hash((struct kru *)&top->data->kru, ticks_now(), hash, 0);

	// VERBOSE_LOG("LOAD %s -> %d\n", kr_cache_top_strkey(key, len), load);
	return load;
}
