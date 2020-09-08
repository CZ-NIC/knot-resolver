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

typedef int (*kr_gc_iter_callback)(const knot_db_val_t * key,
				   gc_record_info_t * info, void *ctx);

int kr_gc_cache_iter(knot_db_t * knot_db, const  kr_cache_gc_cfg_t *cfg,
			kr_gc_iter_callback callback, void *ctx);

const uint16_t *kr_gc_key_consistent(knot_db_val_t key);

/** Printf a *binary* string in a human-readable way. */
void debug_printbin(const char *str, unsigned int len);

