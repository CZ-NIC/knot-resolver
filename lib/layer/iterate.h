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

/* Processing module implementation. */
const knot_layer_api_t *layer_iterate_module(void);
#define LAYER_ITERATE layer_iterate_module()

/*! \brief Result updates the query parent. */
int rr_update_parent(const knot_rrset_t *rr, struct kr_layer_param *param);

/*! \brief Result updates the original query response. */
int rr_update_answer(const knot_rrset_t *rr, struct kr_layer_param *param);

/*! \brief Result updates current nameserver. */
int rr_update_nameserver(const knot_rrset_t *rr, struct kr_layer_param *param);
