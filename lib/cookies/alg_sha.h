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

#include <libknot/cookies/client.h>
#include <libknot/cookies/server.h>

#include "lib/defines.h"

/** HMAC-SHA256-64 client cookie algorithm. */
KR_EXPORT
extern const struct knot_cc_alg knot_cc_alg_hmac_sha256_64;

/** HMAC-SHA256-64 server cookie algorithm. */
KR_EXPORT
extern const struct knot_sc_alg knot_sc_alg_hmac_sha256_64;
