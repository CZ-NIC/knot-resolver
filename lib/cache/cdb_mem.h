/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include "lib/cache/cdb_api.h"
#include "lib/defines.h"

/* Get API implementation for an in-memory cache backend. */
KR_EXPORT KR_CONST
const struct kr_cdb_api *kr_cdb_mem(void);
