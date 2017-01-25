/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
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
