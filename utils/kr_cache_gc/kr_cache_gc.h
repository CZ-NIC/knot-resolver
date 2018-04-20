#pragma once

#include <stddef.h>

typedef struct {
        const char *cache_path;          // path to the LMDB with resolver cache
        unsigned long gc_interval;       // waiting time between two whole garbage collections in usecs (0 = just one-time cleanup)

        size_t temp_keys_space;          // maximum amount of temporary memory for copied keys in bytes (0 = unlimited)

        size_t rw_txn_items;             // maximum number of deleted records per RW transaction (0 = unlimited)
        unsigned long rw_txn_duration;   // maximum duration of RW transaction in usecs (0 = unlimited)
        unsigned long rw_txn_delay;      // waiting time between two RW transactions in usecs
} kr_cache_gc_cfg_t;


int kr_cache_gc(kr_cache_gc_cfg_t *cfg);

#define KR_CACHE_GC_VERSION "0.1"
