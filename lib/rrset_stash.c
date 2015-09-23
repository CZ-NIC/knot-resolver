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

#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>
#include <stdio.h>

#include "lib/defines.h"
#include "lib/rrset_stash.h"

int stash_add(const knot_pkt_t *pkt, map_t *stash, const knot_rrset_t *rr, mm_ctx_t *pool)
{
	(void) pkt;

	/* Stash key = {[1] flags, [1-255] owner, [1-5] type, [1] \x00 } */
	char key[9 + KNOT_DNAME_MAXLEN];
	uint16_t rrtype = rr->type;
	KEY_FLAG_SET(key, KEY_FLAG_NO);

	/* Stash RRSIGs in a special cache, flag them and set type to its covering RR.
	 * This way it the stash won't merge RRSIGs together. */
	if (rr->type == KNOT_RRTYPE_RRSIG) {
		rrtype = knot_rrsig_type_covered(&rr->rrs, 0);
		KEY_FLAG_SET(key, KEY_FLAG_RRSIG);
	}

	uint8_t *key_buf = (uint8_t *)key + 1;
	int ret = knot_dname_to_wire(key_buf, rr->owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower(key_buf);
	/* Must convert to string, as the key must not contain 0x00 */
	ret = snprintf((char *)key_buf + ret - 1, sizeof(key) - KNOT_DNAME_MAXLEN, "%hu", rrtype);
	if (ret <= 0 || ret >= KNOT_DNAME_MAXLEN) {
		return kr_error(EILSEQ);
	}

	/* Check if already exists */
	knot_rrset_t *stashed = map_get(stash, key);
	if (!stashed) {
		stashed = knot_rrset_copy(rr, pool);
		if (!stashed) {
			return kr_error(ENOMEM);
		}
		return map_set(stash, key, stashed);
	}
	/* Merge rdataset */
	return knot_rdataset_merge(&stashed->rrs, &rr->rrs, pool);
}
