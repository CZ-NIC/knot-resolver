/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "lib/cookies/control.h"

/**
 * @brief Sets cookie control context structure.
 * @param ctx cookie control context
 * @param args JSON string describing configuration changes
 * @return true if changes successfully applied
 */
bool config_apply(struct kr_cookie_ctx *ctx, const char *args);

/**
 * @brief Reads cookie control context structure.
 * @param ctx cookie control context
 * @return JSON string or NULL on error
 */
char *config_read(struct kr_cookie_ctx *ctx);

/**
 * @brief Initialises cookie control context to default values.
 * @param ctx cookie control context
 * @return kr_ok() or error code
 */
int config_init(struct kr_cookie_ctx *ctx);

/**
 * @brief Clears the cookie control context.
 * @param ctx cookie control context
 */
void config_deinit(struct kr_cookie_ctx *ctx);
