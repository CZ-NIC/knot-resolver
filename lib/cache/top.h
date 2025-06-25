/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include "lib/mmapped.h"
#include "lib/kru.h"

struct kr_cache_top {
	struct mmapped mmapped;
	struct top_data *data;
	struct kr_cache_top_context *ctx;
};

struct kr_cache_top_context {
	uint32_t bloom[16]; // size of just one cache-line, but probably not aligned (neither kr_request is)
	uint32_t cnt;  // TODO remove this (and propagate to kres-gen)
};

struct top_data {
	uint32_t version;
	uint32_t base_price_norm;
	uint32_t max_decay;
	_Alignas(64) uint8_t kru[];
};

static inline size_t kr_cache_top_entry_size(size_t key_len, size_t data_size) {
	return key_len + data_size;  // TODO increase by a constant as DB overhead?
}
static inline kru_price_t kr_cache_top_entry_price(struct kr_cache_top *top, size_t size) {
	return top->data->base_price_norm / size;
}

KR_EXPORT
int kr_cache_top_init(struct kr_cache_top *top, char *mmap_file, size_t cache_size);

KR_EXPORT
void kr_cache_top_deinit(struct kr_cache_top *top);

KR_EXPORT
void kr_cache_top_access_cdb(struct kr_cache_top *top, void *key, size_t len, char *debug_label); // temporal, TODO remove

KR_EXPORT
void kr_cache_top_access(struct kr_cache_top *top, void *key, size_t key_len, size_t data_size, char *debug_label);

KR_EXPORT
uint16_t kr_cache_top_load(struct kr_cache_top *top, void *key, size_t len);

// ctx has to be kept valid until next call
KR_EXPORT
struct kr_cache_top_context *kr_cache_top_context_switch(struct kr_cache_top *top, struct kr_cache_top_context *ctx, char *debug_label);

KR_EXPORT
char *kr_cache_top_strkey(void *key, size_t len);
