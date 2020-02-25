/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
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
