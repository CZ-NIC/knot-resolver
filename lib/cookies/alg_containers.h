/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
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
