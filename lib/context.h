/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <libknot/internal/mempattern.h>
#include <libknot/internal/lists.h>

#include "lib/cache.h"

/*!
 * \brief Name resolution context.
 *
 * Resolution context provides basic services like cache, configuration and options.
 *
 * \note This structure is persistent between name resolutions and may
 *       be shared between threads.
 */
struct kr_context
{
	struct kr_cache *cache;
	list_t layers;
	unsigned options;
	mm_ctx_t *pool;
};

/*!
 * \brief Initialize query resolution context.
 * \param ctx context to be initialized
 * \param mm memory context
 * \return KNOT_E*
 */
int kr_context_init(struct kr_context *ctx, mm_ctx_t *mm);

/*!
 * \brief Deinitialize query resolution context.
 * \param ctx context to be deinitialized
 * \return KNOT_E*
 */
int kr_context_deinit(struct kr_context *ctx);
