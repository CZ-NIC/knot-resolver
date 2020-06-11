/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>

struct worker_ctx;
/** Zone import context (opaque).  */
struct zone_import_ctx;

/**
 * Completion callback
 *
 * @param state -1 - fail
 *               0 - success
 *               1 - success, but there are non-critical errors
 * @param pointer to user data
 */
typedef void (*zi_callback)(int state, void *param);

/**
 * Allocate and initialize zone import context.
 *
 * @param worker pointer to worker state
 * @return NULL or pointer to zone import context.
 */
struct zone_import_ctx *zi_allocate(struct worker_ctx *worker,
				    zi_callback cb, void *param);

/** Free zone import context. */
void zi_free(struct zone_import_ctx *z_import);

/**
 * Import zone from file.
 *
 * @note only root zone import is supported; origin must be NULL or "."
 * @param z_import pointer to zone import context
 * @param zone_file zone file name
 * @param origin default origin
 * @param rclass default class
 * @param ttl    default ttl
 * @return 0 or an error code
 */
int zi_zone_import(struct zone_import_ctx *z_import,
		   const char *zone_file, const char *origin,
		   uint16_t rclass, uint32_t ttl);

/**
 * Check if import already in process.
 *
 * @param z_import pointer to zone import context.
 * @return true if import already in process; false otherwise.
 */
bool zi_import_started(struct zone_import_ctx *z_import);
