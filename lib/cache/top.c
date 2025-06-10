/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <limits.h>
#include "lib/utils.h"
#include "lib/defines.h"
#include "lib/cache/top.h"
#include "lib/mmapped.h"
#include "lib/kru.h"

// #ifdef LOG_GRP_MDB
#define VERBOSE_LOG(...) printf("GC KRU " __VA_ARGS__)

#define FILE_FORMAT_VERSION 1  // fail if different

#define TICK_MSEC    1000
#define BASE_PRICE   (((kru_price_t)1) << (KRU_PRICE_BITS - 16))  // increment by ones (16-bit)
	// -> instant limit: ~2^16     // TODO -> 2^14 ?
#define MAX_DECAY    (BASE_PRICE / 2)  // per sec
	// -> rate limit: 1/2 per sec  (more frequent accesses are incomparable)
	// -> half-life: ~ 25h 14min   // TODO -> 5h ?

struct top_data {
	uint32_t version;
	uint32_t base_price;
	uint32_t max_decay;
	_Alignas(64) uint8_t kru[];
};


static inline uint32_t ticks_now(void)
{
	// TODO use clock_gettime directly or maintain time offset
	return kr_now() / TICK_MSEC;  // not working over reboots
}

static inline bool first_access_ro(struct kr_cache_top_context *ctx, kru_hash_t hash) {
	// struct kr_cache_top_context { uint64_t bloom[4]; }
	static_assert(sizeof(((struct kr_cache_top_context *)0)->bloom[0]) * 8 == 64);
	static_assert(sizeof(((struct kr_cache_top_context *)0)->bloom)    * 8 == 64 * 4);
		// expected around 16 unique cache accesses per request context;
		// prob. of collision of the 16th unique access with the preceeding ones: 1/510;
		// 32nd access: 1/45; 64th access: 1/6

	uint8_t *h = (uint8_t *)&hash;
	static_assert(sizeof(kru_hash_t) >= 4);

	bool accessed = 1ull &
		(ctx->bloom[0] >> (h[0] % 64)) &
		(ctx->bloom[1] >> (h[1] % 64)) &
		(ctx->bloom[2] >> (h[2] % 64)) &
		(ctx->bloom[3] >> (h[3] % 64));

	return !accessed;
}

static inline bool first_access(struct kr_cache_top_context *ctx, kru_hash_t hash) {
	if (!first_access_ro(ctx, hash)) return false;

	uint8_t *h = (uint8_t *)&hash;
	static_assert(sizeof(kru_hash_t) >= 4);

	ctx->bloom[0] |= 1ull << (h[0] % 64);
	ctx->bloom[1] |= 1ull << (h[1] % 64);
	ctx->bloom[2] |= 1ull << (h[2] % 64);
	ctx->bloom[3] |= 1ull << (h[3] % 64);

	kr_assert(!first_access_ro(ctx, hash));

	if (++ctx->cnt > 16) {
		VERBOSE_LOG("BLOOM overfull (%d unique accesses)\n", ctx->cnt);
	}

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
		.version      = (FILE_FORMAT_VERSION << 1) | kru_using_avx2(),
		.base_price   = BASE_PRICE,
		.max_decay    = MAX_DECAY
	};

	size_t header_size = offsetof(struct top_data, max_decay) + sizeof(header.max_decay);
	static_assert(  // no padding up to .max_decay
		offsetof(struct top_data, max_decay) ==
			sizeof(header.version) +
			sizeof(header.base_price),
		"detected padding with undefined data inside mmapped header");

	if (cache_size == 0) {
		header_size = offsetof(struct top_data, base_price);
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
static char *str_key(void *key, size_t len) {
	static char str[401];
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

void kr_cache_top_access(struct kr_cache_top *top, void *key, size_t len, char *debug_label)
{
	kru_hash_t hash = KRU.hash_bytes((struct kru *)&top->data->kru, (uint8_t *)key, len);
	const bool unique = top->ctx ? first_access(top->ctx, hash) : true;
	if (unique) {
		KRU.load_hash((struct kru *)&top->data->kru, ticks_now(), hash, top->data->base_price);
	}
	VERBOSE_LOG("ACCESS %-19s %s%s%s\n", debug_label, str_key(key, len), unique ? "" : " (SKIP)", top->ctx ? "" : "(NO_CONTEXT, PASS)");
}

// temporal logging one level under _access
void kr_cache_top_access_cdb(struct kr_cache_top *top, void *key, size_t len, char *debug_label)
{

	// VERBOSE_LOG("ACCESS   %-17s %s\n", debug_label, str_key(key, len));
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

	VERBOSE_LOG("LOAD %s -> %d\n", str_key(key, len), load);
	return load;
}
