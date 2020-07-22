/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include "lib/cache/cdb_api.h"
#include "lib/defines.h"

/** Get API implementation for LMDB.
 *
 * The properties differ a bit based on whether it's meant for cache or rule DB.
 */
KR_EXPORT KR_CONST
const struct kr_cdb_api *kr_cdb_lmdb(bool is_cache);

KR_EXPORT
knot_db_t *knot_db_t_kres2libknot(const knot_db_t * db);
