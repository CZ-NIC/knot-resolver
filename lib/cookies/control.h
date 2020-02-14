/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/defines.h"

/** Holds secret quantity. */
struct kr_cookie_secret {
	size_t size; /*!< Secret quantity size. */
	uint8_t data[]; /*!< Secret quantity data. */
};

/** Holds settings that have direct influence on cookie values computation. */
struct kr_cookie_comp {
	struct kr_cookie_secret *secr; /*!< Secret data. */
	int alg_id; /*!< Cookie algorithm identifier. */
};

/** Holds settings that control client/server cookie behaviour. */
struct kr_cookie_settings {
	bool enabled; /**< Enable/disables DNS cookies functionality. */

	struct kr_cookie_comp current; /**< Current cookie settings. */
	struct kr_cookie_comp recent; /**< Recent cookie settings. */
};

/** DNS cookies controlling structure. */
struct kr_cookie_ctx {
	struct kr_cookie_settings clnt; /**< Client settings. */
	struct kr_cookie_settings srvr; /**< Server settings. */
};
