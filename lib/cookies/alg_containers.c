/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdint.h>
#include <stdlib.h>

#include <libknot/cookies/alg-fnv64.h>

#include "lib/cookies/alg_containers.h"
#include "lib/cookies/alg_sha.h"

const struct knot_cc_alg *kr_cc_alg_get(int id)
{
	/*
	 * Client algorithm identifiers are used to index this array of
	 * pointers.
	 */
	static const struct knot_cc_alg *const cc_algs[] = {
		/* 0 */ &knot_cc_alg_fnv64,
		/* 1 */ &knot_cc_alg_hmac_sha256_64
	};

	if (id >= 0 && id < 2) {
		return cc_algs[id];
	}

	return NULL;
}

const knot_lookup_t kr_cc_alg_names[] = {
	{ 0, "FNV-64" },
	{ 1, "HMAC-SHA256-64" },
	{ -1, NULL }
};

const struct knot_sc_alg *kr_sc_alg_get(int id)
{
	/*
	 * Server algorithm identifiers are used to index this array of
	 * pointers.
	 */
	static const struct knot_sc_alg *const sc_algs[] = {
		/* 0 */ &knot_sc_alg_fnv64,
		/* 1 */ &knot_sc_alg_hmac_sha256_64
	};

	if (id >= 0 && id < 2) {
		return sc_algs[id];
	}

	return NULL;
}

const knot_lookup_t kr_sc_alg_names[] = {
	{ 0, "FNV-64" },
	{ 1, "HMAC-SHA256-64" },
	{ -1, NULL }
};
