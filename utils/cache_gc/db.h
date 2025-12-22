/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <lib/cache/api.h>
#include <libknot/libknot.h>

#include "kr_cache_gc.h"

int kr_gc_cache_open(const char *cache_path, struct kr_cache *kres_db,
		     knot_db_t ** libknot_db);

/** A wrapper around kr_cdb_api::check_health that keeps libknot_db up to date.
 * \return zero or negative error code. */
int kr_gc_cache_check_health(struct kr_cache *kres_db, knot_db_t ** libknot_db);

void kr_gc_cache_close(struct kr_cache *kres_db, knot_db_t * knot_db);

struct kr_gc_cat_record_info;
typedef void (*kr_gc_iter_callback)(struct kr_cache_top *top, struct kr_gc_cat_record_info *info, void *ctx);

int kr_gc_cache_iter(knot_db_t * knot_db, struct kr_cache_top *top, const  kr_cache_gc_cfg_t *cfg,
			kr_gc_iter_callback callback, void *ctx);

/** Printf a *binary* string in a human-readable way. */
void debug_printbin(const char *str, unsigned int len);

/** Block run in --verbose mode; optimized when not run. */
#define VERBOSE_STATUS __builtin_expect(KR_LOG_LEVEL_IS(LOG_DEBUG), false)
/* TODO: replace when solving GC logging properly */

