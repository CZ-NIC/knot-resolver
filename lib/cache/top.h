/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include "lib/mmapped.h"

union kr_cache_top {
	struct mmapped mmapped;
	struct top_data *data;
};
static_assert(&((union kr_cache_top *)0)->mmapped.mem == (void *)&((union kr_cache_top *)0)->data);


KR_EXPORT
int kr_cache_top_init(union kr_cache_top *top, char *mmap_file, size_t cache_size);

KR_EXPORT
void kr_cache_top_deinit(union kr_cache_top *top);

KR_EXPORT
void kr_cache_top_access_cdb(union kr_cache_top *top, void *key, size_t len, char *debug_label); // temporal, TODO remove

KR_EXPORT
void kr_cache_top_access(union kr_cache_top *top, void *key, size_t len, char *debug_label);

KR_EXPORT
uint16_t kr_cache_top_load(union kr_cache_top *top, void *key, size_t len);
