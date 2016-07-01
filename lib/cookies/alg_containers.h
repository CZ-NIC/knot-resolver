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

#include <libknot/cookies/client.h>
#include <libknot/cookies/server.h>
#include <libknot/lookup.h>

#include "lib/defines.h"

/** Client algorithm identifiers are used as index into this array of pointers. */
KR_EXPORT
extern const struct knot_cc_alg *const kr_cc_algs[];

/** Binds client algorithm identifiers onto names. */
KR_EXPORT
extern const knot_lookup_t kr_cc_alg_names[];

/** Server algorithm identifiers are used as index into this array of pointers. */
KR_EXPORT
extern const struct knot_sc_alg *const kr_sc_algs[];

/** Binds server algorithm identifiers onto names. */
KR_EXPORT
extern const knot_lookup_t kr_sc_alg_names[];

/** Maximal size of a cookie option. */
#define KR_COOKIE_OPT_MAX_LEN (KNOT_EDNS_OPTION_HDRLEN + KNOT_OPT_COOKIE_CLNT + KNOT_OPT_COOKIE_SRVR_MAX)
