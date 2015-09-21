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
#include <libknot/rdataset.h>
#include <libknot/rrset.h>
#include <libknot/packet/wire.h>

#include "lib/defines.h"
#include "lib/dnssec/ta.h"

knot_rrset_t *kr_ta_get(map_t *trust_anchors, const knot_dname_t *name)
{
	return map_get(trust_anchors, (const char *)name);
}

int kr_ta_add(map_t *trust_anchors, const knot_dname_t *name, uint16_t type,
               uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
	if (!trust_anchors || !name || !rdata) {
		return kr_error(EINVAL);
	}

	/* Convert DNSKEY records to DS */
	switch (type) {
	case KNOT_RRTYPE_DS: break; /* OK */
	case KNOT_RRTYPE_DNSKEY:
#warning TODO: convert DNSKEY -> DS here
		return kr_error(ENOSYS);
		break;
	default: return kr_error(EINVAL);
	}

	/* Create new RRSet or use existing */
	bool is_new_key = false;
	knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, name);
	if (!ta_rr) { 
		ta_rr = knot_rrset_new(name, type, KNOT_CLASS_IN, NULL);
		is_new_key = true;
	}
	/* Merge-in new key data */
	if (!ta_rr || knot_rrset_add_rdata(ta_rr, rdata, rdlen, ttl, NULL) != 0) {
		knot_rrset_free(&ta_rr, NULL);
		return kr_error(ENOMEM);
	}
	/* Reinsert */
	if (is_new_key) {
		map_set(trust_anchors, (const char *)name, ta_rr);
	}

	return kr_ok();	
}

int kr_ta_covers(map_t *trust_anchors, const knot_dname_t *name)
{
	while(name) {
		if (kr_ta_get(trust_anchors, name)) {
			return true;
		}
		if (name[0] == '\0') {
			return false;
		}
		name = knot_wire_next_label(name, NULL);
	}
	return false;
}

/* Delete record data */
static int del_record(const char *k, void *v, void *ext)
{
	knot_rrset_t *ta_rr = v;
	knot_rrset_free(&ta_rr, NULL);
	return 0;
}

int kr_ta_del(map_t *trust_anchors, const knot_dname_t *name)
{
	knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, name);
	if (ta_rr) {
		del_record(NULL, ta_rr, NULL);
		map_del(trust_anchors, (const char *)name);
	}
	return kr_ok();
}

void kr_ta_clear(map_t *trust_anchors)
{
	map_walk(trust_anchors, del_record, NULL);
	map_clear(trust_anchors);
}
