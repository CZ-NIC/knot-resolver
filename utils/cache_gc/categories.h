/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "kr_cache_gc.h"

typedef uint8_t category_t;

#define CATEGORIES 100		// number of categories

category_t kr_gc_categorize(gc_record_info_t * info);
