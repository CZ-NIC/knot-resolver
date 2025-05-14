/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "kr_cache_gc.h"
#include "lib/cache/top.h"

typedef uint8_t category_t;

#define CATEGORIES 100		// number of categories

category_t kr_gc_categorize(union kr_cache_top *top, gc_record_info_t * info, void *key, size_t key_len);
