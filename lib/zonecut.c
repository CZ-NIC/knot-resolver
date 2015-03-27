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

#include <dnssec/random.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/packet/wire.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/aaaa.h>

#include "lib/zonecut.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/layer.h"

/* Root hint descriptor. */
struct hint_info {
	const knot_dname_t *name;
	const char *addr;
};

/* Initialize with SBELT name servers. */
#define U8(x) (const uint8_t *)(x)
#define HINT_COUNT 13
static const struct hint_info SBELT[HINT_COUNT] = {
        { U8("\x01""a""\x0c""root-servers""\x03""net"), "198.41.0.4" },
        { U8("\x01""b""\x0c""root-servers""\x03""net"), "192.228.79.201" },
        { U8("\x01""c""\x0c""root-servers""\x03""net"), "192.33.4.12" },
        { U8("\x01""d""\x0c""root-servers""\x03""net"), "199.7.91.13" },
        { U8("\x01""e""\x0c""root-servers""\x03""net"), "192.203.230.10" },
        { U8("\x01""f""\x0c""root-servers""\x03""net"), "192.5.5.241" },
        { U8("\x01""g""\x0c""root-servers""\x03""net"), "192.112.36.4" },
        { U8("\x01""h""\x0c""root-servers""\x03""net"), "128.63.2.53" },
        { U8("\x01""i""\x0c""root-servers""\x03""net"), "192.36.148.17" },
        { U8("\x01""j""\x0c""root-servers""\x03""net"), "192.58.128.30" },
        { U8("\x01""k""\x0c""root-servers""\x03""net"), "193.0.14.129" },
        { U8("\x01""l""\x0c""root-servers""\x03""net"), "199.7.83.42" },
        { U8("\x01""m""\x0c""root-servers""\x03""net"), "202.12.27.33" }
};

int kr_init_zone_cut(struct kr_zonecut *cut)
{
	if (cut == NULL) {
		return KNOT_EINVAL;
	}

	const unsigned hint_id = dnssec_random_uint16_t() % HINT_COUNT;
	const struct hint_info *hint = &SBELT[hint_id];

	kr_set_zone_cut(cut, U8(""), hint->name);

	/* Prefetch address. */
	return sockaddr_set(&cut->addr, AF_INET, hint->addr, 53);
}

int kr_set_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, const knot_dname_t *ns)
{
	if (cut == NULL || name == NULL) {
		return KNOT_EINVAL;
	}

	/* Set current NS and zone cut. */
	knot_dname_to_wire(cut->name, name, KNOT_DNAME_MAXLEN);
	knot_dname_to_wire(cut->ns, ns, KNOT_DNAME_MAXLEN);

	/* Invalidate address. */
	cut->addr.ss_family = AF_UNSPEC;

	return KNOT_EOK;
}

int kr_set_zone_cut_addr(struct kr_zonecut *cut, const knot_rrset_t *rr, uint16_t i)
{
	int ret = KNOT_EOK;

	switch(rr->type) {
	case KNOT_RRTYPE_A:
		ret = knot_a_addr(&rr->rrs, i, (struct sockaddr_in *)&cut->addr);
		break;
	case KNOT_RRTYPE_AAAA:
		ret = knot_aaaa_addr(&rr->rrs, i, (struct sockaddr_in6 *)&cut->addr);
		break;
	default:
		return KNOT_EINVAL;
	}

	sockaddr_port_set(&cut->addr, KR_DNS_PORT);

	return ret;
}

/** Fetch address for zone cut. */
static int fetch_addr(struct kr_zonecut *cut, namedb_txn_t *txn, uint32_t timestamp)
{
	/* Fetch nameserver address from cache. */
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, cut->ns, 0, KNOT_CLASS_IN);
	cached_rr.type = KNOT_RRTYPE_A;
	if (kr_cache_peek(txn, &cached_rr, &timestamp) != KNOT_EOK) {
		cached_rr.type = KNOT_RRTYPE_AAAA;
		if (kr_cache_peek(txn, &cached_rr, &timestamp) != KNOT_EOK) {
			return KNOT_ENOENT;
		}
	}
	/* Find first valid record. */
	uint16_t i = 0;
	for (; i < cached_rr.rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&cached_rr.rrs, i);
		if (knot_rdata_ttl(rd) > timestamp) {
			break;
		}
	}

	return kr_set_zone_cut_addr(cut, &cached_rr, i);
}

/** Fetch best NS for zone cut. */
static int fetch_ns(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp)
{
	uint32_t drift = timestamp;
	knot_rrset_t cached_rr;
	knot_rrset_init(&cached_rr, (knot_dname_t *)name, KNOT_RRTYPE_NS, KNOT_CLASS_IN);
	int ret = kr_cache_peek(txn, &cached_rr, &drift);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	/* Accept only if has address records cached. */
	for (unsigned i = 0; i < cached_rr.rrs.rr_count; ++i) {
		kr_set_zone_cut(cut, name, knot_ns_name(&cached_rr.rrs, i));
		ret = fetch_addr(cut, txn, timestamp);
		if (ret == KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int kr_find_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp)
{
	if (cut == NULL || name == NULL) {
		return KNOT_EINVAL;
	}

	/* No cache, start with SBELT. */
	if (txn == NULL) {
		return kr_init_zone_cut(cut);
	}

	/* Start at QNAME. */
	while (true) {
		if (fetch_ns(cut, name, txn, timestamp) == KNOT_EOK) {
			return KNOT_EOK;
		}
		/* Subtract label from QNAME. */
		if (name[0] == '\0') {
			break;
		}
		name = knot_wire_next_label(name, NULL);
	}

	/* Name server not found, start with SBELT. */
	return kr_init_zone_cut(cut);
}
