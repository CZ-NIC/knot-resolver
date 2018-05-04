#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
        int64_t expires_in;         // < 0 => already expired
        uint16_t rrtype;
        uint8_t no_labels;          // 0 == ., 1 == root zone member, 2 == TLD member ...
        uint8_t rank;
        size_t entry_size;          // amount of bytes occupied in cache by this record
} gc_record_info_t;

typedef struct {
        const char *cache_path;          // path to the LMDB with resolver cache
        unsigned long gc_interval;       // waiting time between two whole garbage collections in usecs (0 = just one-time cleanup)

        size_t temp_keys_space;          // maximum amount of temporary memory for copied keys in bytes (0 = unlimited)

        size_t rw_txn_items;             // maximum number of deleted records per RW transaction (0 = unlimited)
        unsigned long rw_txn_duration;   // maximum duration of RW transaction in usecs (0 = unlimited)
        unsigned long rw_txn_delay;      // waiting time between two RW transactions in usecs
} kr_cache_gc_cfg_t;


int kr_cache_gc(kr_cache_gc_cfg_t *cfg);

#define KR_CACHE_GC_VERSION "0.2"
