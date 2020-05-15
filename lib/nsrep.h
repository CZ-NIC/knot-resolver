/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <netinet/in.h>
#include "lib/utils.h"

struct kr_nsrep
{
    knot_dname_t* name;
    union inaddr addr[4];
};

typedef struct kr_nsrep_rtt_lru
{

} kr_nsrep_rtt_lru_t;

typedef struct kr_nsrep_lru {

} kr_nsrep_lru_t;

typedef struct kr_nsrep_rtt_lru_entry {

} kr_nsrep_rtt_lru_entry_t;
