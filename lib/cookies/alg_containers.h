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
#include <libknot/lookup.h>

#include "lib/defines.h"

/**
 * @brief Returns pointer to client cookie algorithm.
 *
 * @param id algorithm identifier as defined by lookup table
 * @return   pointer to algorithm structure with given id or NULL on error
 */
KR_EXPORT
const struct knot_cc_alg *kr_cc_alg_get(int id);

/** Binds client algorithm identifiers onto names. */
KR_EXPORT
extern const knot_lookup_t kr_cc_alg_names[];

/**
 * @brief Returns pointer to server cookie algorithm.
 *
 * @param id algorithm identifier as defined by lookup table
 * @return   pointer to algorithm structure with given id or NULL on error
 */
KR_EXPORT
const struct knot_sc_alg *kr_sc_alg_get(int id);

/** Binds server algorithm identifiers onto names. */
KR_EXPORT
extern const knot_lookup_t kr_sc_alg_names[];
