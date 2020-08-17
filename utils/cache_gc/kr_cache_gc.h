/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
	size_t entry_size;	// amount of bytes occupied in cache by this record
	bool valid;		// fields further down are valid (ignore them if false)
	int64_t expires_in;	// < 0 => already expired
	uint16_t rrtype;
	uint8_t no_labels;	// 0 == ., 1 == root zone member, 2 == TLD member ...
	uint8_t rank;
} gc_record_info_t;

typedef struct {
	const char *cache_path;	// path to the LMDB with resolver cache
	unsigned long gc_interval;	// waiting time between two whole garbage collections in usecs (0 = just one-time cleanup)

	size_t temp_keys_space;	// maximum amount of temporary memory for copied keys in bytes (0 = unlimited)

	size_t rw_txn_items;	// maximum number of deleted records per RW transaction (0 = unlimited)
	size_t ro_txn_items;	// maximum number of iterated records (RO transactions, 0 = unlimited)
	unsigned long rw_txn_duration;	// maximum duration of RW transaction in usecs (0 = unlimited)
	unsigned long rw_txn_delay;	// waiting time between two RW transactions in usecs

	uint8_t cache_max_usage;	// maximum cache usage before triggering GC (percent)
	uint8_t cache_to_be_freed;	// percent of current cache usage to be freed during GC

	bool dry_run;
} kr_cache_gc_cfg_t;

/** State persisting across kr_cache_gc() invocations (opaque).
 * NULL pointer represents a clean state. */
typedef struct kr_cache_gc_state kr_cache_gc_state_t;

/** Do one iteration of cache-size check and (if necessary) GC pass. */
int kr_cache_gc(kr_cache_gc_cfg_t *cfg, kr_cache_gc_state_t **state);
void kr_cache_gc_free_state(kr_cache_gc_state_t **state);

