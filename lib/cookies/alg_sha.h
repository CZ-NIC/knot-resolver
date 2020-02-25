/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/cookies/client.h>
#include <libknot/cookies/server.h>

#include "lib/defines.h"

/* These structures are not meant to be part of public interface. */

/** HMAC-SHA256-64 client cookie algorithm. */
extern const struct knot_cc_alg knot_cc_alg_hmac_sha256_64;

/** HMAC-SHA256-64 server cookie algorithm. */
extern const struct knot_sc_alg knot_sc_alg_hmac_sha256_64;
