/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <libknot/internal/mempattern.h>
#include <libknot/internal/lists.h>

#include "lib/module.h"
#include "lib/cache.h"

/** \addtogroup resolution
 * @{ 
 */

/**
 * Name resolution context.
 *
 * Resolution context provides basic services like cache, configuration and options.
 *
 * @note This structure is persistent between name resolutions and may
 *       be shared between threads.
 */
struct kr_context
{
    mm_ctx_t *pool;
    struct kr_cache *cache;
    struct kr_module *modules;
    size_t mod_loaded;
    size_t mod_reserved;
    uint32_t options;
};

/**
 * Initialize query resolution context.
 * @param ctx context to be initialized
 * @param mm memory context
 * @return KNOT_E*
 */
int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm);

/**
 * Deinitialize query resolution context.
 * @param ctx context to be deinitialized
 * @return KNOT_E*
 */
int kr_context_deinit(struct kr_context *ctx);

/**
 * Register module to context.
 * @param ctx context
 * @param module_name
 * @return KNOT_E*
 */
int kr_context_register(struct kr_context *ctx, const char *module_name);

/** @} */
