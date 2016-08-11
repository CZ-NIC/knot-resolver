/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
