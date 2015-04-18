/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "lib/layer.h"
#include "lib/rplan.h"

/* Processing module implementation. */
extern const knot_layer_api_t *iterate_layer(void);

/**
 * Result updates the query parent.
 * @note Hint is an index of chosen RR in the set.
 */
int rr_update_parent(const knot_rrset_t *rr, unsigned hint, struct kr_layer_param *param);

/**
 * Result updates the original query response.
 * @note When \a hint is KNOT_PF_FREE, RR is treated as a copy and answer takes its ownership.
 */
int rr_update_answer(const knot_rrset_t *rr, unsigned hint, struct kr_layer_param *param);

/* Processing module implementation. */
const knot_layer_api_t *iterate_layer(void);