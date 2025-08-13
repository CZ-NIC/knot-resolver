/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/// Top uses KRU to maintain statistics about recently used cache entries
/// for deciding what to evict during garbage collection.
///
/// The statistics are stored persistently beside LMDB data file
/// and their half-life is currently 5 hours, taking ~3-day traffic into account.
/// Each accessed cache entry is counted only once within a single request context
/// and the price of the access is inversely proportional to the size of the cache entry;
/// thus accesses per byte are the measure.
///
/// The keys currently stored in KRU and in cache need not necessarily correspond.
/// It is possible that a key is reinserted into cache after it was previously evicted
/// likely due to the expired TTL, but still has high load assinged in KRU.
/// Or that the KRU load of a key decreased to zero after hours or days of inactivity,
/// but there was no need to remove the (possibly expired) entry from the cache.

#pragma once
#include <stdalign.h>
#include "lib/mmapped.h"

struct kr_request;

/// Data related to open cache.
struct kr_cache_top {
	struct mmapped mmapped;
	struct top_data *data;
};

/// Part of the previous, shared between all processes.
struct top_data {
	uint32_t version;
	uint32_t base_price_norm;
	uint32_t max_decay;
	alignas(64) uint8_t kru[];
};

/// Part of kr_request to avoid counting repeated cache accesses multiple times during single request.
struct kr_cache_top_context {
	uint32_t bloom[32];
};

#define KR_CACHE_SIZE_OVERHEAD  16 // B, just guess, probably more; size = key + data + DB overhead

/// Approximate size of a cache entry.
static inline size_t kr_cache_top_entry_size(size_t key_len, size_t data_size) {
	return key_len + data_size + KR_CACHE_SIZE_OVERHEAD;
}

/// Price of a cache entry access in KRU based on the entry size.
static inline uint32_t kr_cache_top_entry_price(struct kr_cache_top *top, size_t size) {
	return top->data->base_price_norm / size;
}

/// Size of the top data as part of the cache size, LMDB should occupy the rest;
/// currently between 6 and 13 %.
KR_EXPORT
size_t kr_cache_top_get_size(size_t cache_size);

/// Initialize memory shared between processes, possibly using existing data in mmap_file.
/// If cache_size differs from the previously used value, the data are cleared,
/// otherwise they are persistent across restarts.
KR_EXPORT
int kr_cache_top_init(struct kr_cache_top *top, char *mmap_file, size_t cache_size);

/// Deinitialize shared memory, keeping the data stored in file.
KR_EXPORT
void kr_cache_top_deinit(struct kr_cache_top *top);

/// Charge cache access to the accessed key
/// unless it was already accessed in the current request context.
KR_EXPORT
void kr_cache_top_access(struct kr_request *req, void *key, size_t key_len, size_t data_size, char *debug_label);
	// debug_label is currently not used, TODO remove?

/// Get current KRU load value assigned to the given cache entry key.
KR_EXPORT
uint16_t kr_cache_top_load(struct kr_cache_top *top, void *key, size_t len);

/// Return readable string representation of a cache key in a statically allocated memory.
/// By default printable characters are kept unchanged and NULL-bytes are printed as '|'.
/// Where numeric values are expected (CACHE_KEY_DEF) or non-printable characters occur,
/// either decimal bytes in form <0.1.2> or hexadecimal in form <x000102x> are printed.
/// Decimal form is used for RRTYPEs and IPv4; hexadecimal for NSEC3 hashes, IPv6
/// and unexpected unprintable characters or '|', '<', '>' for unambiguity.
KR_EXPORT
char *kr_cache_top_strkey(void *key, size_t len);
