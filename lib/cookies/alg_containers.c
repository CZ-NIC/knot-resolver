/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <libknot/cookies/alg-fnv64.h>

#include "lib/cookies/alg_containers.h"
#include "lib/cookies/alg_sha.h"

const struct kr_cc_alg_descr kr_cc_algs[] = {
	{ "FNV-64", &knot_cc_alg_fnv64 },
	{ "HMAC-SHA256-64", &knot_cc_alg_hmac_sha256_64 },
	{ NULL, NULL }
};

const struct kr_cc_alg_descr *kr_cc_alg(const struct kr_cc_alg_descr cc_algs[],
                                        const char *name)
{
	if (!cc_algs || !name) {
		return NULL;
	}

	const struct kr_cc_alg_descr *aux_ptr = cc_algs;
	while (aux_ptr && aux_ptr->alg && aux_ptr->alg->gen_func) {
		assert(aux_ptr->name);
		if (strcmp(aux_ptr->name, name) == 0) {
			return aux_ptr;
		}
		++aux_ptr;
	}

	return NULL;
}

const struct kr_sc_alg_descr kr_sc_algs[] = {
	{ "FNV-64", &knot_sc_alg_fnv64 },
	{ "HMAC-SHA256-64", &knot_sc_alg_hmac_sha256_64 },
	{ NULL, NULL }
};

const struct kr_sc_alg_descr *kr_sc_alg(const struct kr_sc_alg_descr sc_algs[],
                                        const char *name)
{
	if (!sc_algs || !name) {
		return NULL;
	}

	const struct kr_sc_alg_descr *aux_ptr = sc_algs;
	while (aux_ptr && aux_ptr->alg && aux_ptr->alg->hash_func) {
		assert(aux_ptr->name);
		if (strcmp(aux_ptr->name, name) == 0) {
			return aux_ptr;
		}
		++aux_ptr;
	}

	return NULL;
}
