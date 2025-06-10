/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include "lib/mmapped.h"

struct kr_cache_top {
	struct mmapped mmapped;
	struct top_data *data;
	struct kr_cache_top_context *ctx;
};

struct kr_cache_top_context {
	uint64_t bloom[4];
	uint32_t cnt;  // TODO remove this (and propagate to kres-gen)
};


KR_EXPORT
int kr_cache_top_init(struct kr_cache_top *top, char *mmap_file, size_t cache_size);

KR_EXPORT
void kr_cache_top_deinit(struct kr_cache_top *top);

KR_EXPORT
void kr_cache_top_access_cdb(struct kr_cache_top *top, void *key, size_t len, char *debug_label); // temporal, TODO remove

KR_EXPORT
void kr_cache_top_access(struct kr_cache_top *top, void *key, size_t len, char *debug_label);

KR_EXPORT
uint16_t kr_cache_top_load(struct kr_cache_top *top, void *key, size_t len);

// ctx has to be kept valid until next call
KR_EXPORT
struct kr_cache_top_context *kr_cache_top_context_switch(struct kr_cache_top *top, struct kr_cache_top_context *ctx, char *debug_label);
