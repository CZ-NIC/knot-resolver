/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include "lib/cache/cdb_api.h"
#include "lib/defines.h"

KR_EXPORT KR_CONST
const struct kr_cdb_api *kr_cdb_lmdb(void);

/** Create a pointer for knot_db_lmdb_api.  You free() it to release it. */
KR_EXPORT
knot_db_t *kr_cdb_pt2knot_db_t(kr_cdb_pt db);

