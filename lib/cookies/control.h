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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <libknot/rrtype/opt-cookie.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/cookies/alg_containers.h"
#include "lib/cache.h"
#include "lib/defines.h"

/** Holds secret quantity. */
struct kr_cookie_secret {
	size_t size; /*!< Secret quantity size. */
	uint8_t data[]; /*!< Secret quantity data. */
};

/** Default cookie TTL. */
#define DFLT_COOKIE_TTL 72000

/** Holds settings that have direct influence on client cookie values. */
struct kr_clnt_cookie_settings {
	struct kr_cookie_secret *csec; /*!< Client secret data. */
	int calg_id; /*!< Client cookie algorithm identifier. */
};

/** Holds settings that control client behaviour. */
struct kr_clnt_cookie_ctx {
	bool enabled; /**< Enable/disables client DNS cookies functionality. */

	struct kr_clnt_cookie_settings current; /**< Current cookie client settings. */
	struct kr_clnt_cookie_settings recent; /**< Current cookie client settings. */

	uint32_t cache_ttl; /**< TTL used when caching cookies */
};

/** Holds settings that have direct influence on server cookie values. */
struct kr_srvr_cookie_settings {
	struct kr_cookie_secret *ssec; /*!< Server secret data. */
	int salg_id; /**< Server cookie algorithm identifier. */
};

/** Holds settings that control server behaviour. */
struct kr_srvr_cookie_ctx {
	bool enabled; /**< Enable/disables server DNS cookies functionality. */

	struct kr_srvr_cookie_settings current; /**< Current cookie server settings. */
	struct kr_srvr_cookie_settings recent; /**< Current cookie server settings. */
};

/** DNS cookies controlling structure. */
struct kr_cookie_ctx {
	struct kr_clnt_cookie_ctx clnt; /**< Client settings. */
	struct kr_srvr_cookie_ctx srvr; /**< Server settings. */
};

/** Global cookie control context. */
KR_EXPORT
extern struct kr_cookie_ctx kr_glob_cookie_ctx;
