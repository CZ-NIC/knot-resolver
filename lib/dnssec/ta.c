/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <contrib/cleanup.h>
#include <libknot/descriptor.h>
#include <libknot/rdataset.h>
#include <libknot/rrset.h>
#include <libknot/packet/wire.h>
#include <dnssec/key.h>
#include <dnssec/error.h>

#include "lib/defines.h"
#include "lib/dnssec/ta.h"
#include "lib/resolve.h"
#include "lib/utils.h"

knot_rrset_t *kr_ta_get(map_t *trust_anchors, const knot_dname_t *name)
{
	return map_get(trust_anchors, (const char *)name);
}

const knot_dname_t *kr_ta_get_longest_name(map_t *trust_anchors, const knot_dname_t *name)
{
	while(name) {
		if (kr_ta_get(trust_anchors, name)) {
			return name;
		}
		if (name[0] == '\0') {
			break;
		}
		name = knot_wire_next_label(name, NULL);
	}
	return NULL;
}

/* @internal Create DS from DNSKEY, caller MUST free dst if successful. */
static int dnskey2ds(dnssec_binary_t *dst, const knot_dname_t *owner, const uint8_t *rdata, uint16_t rdlen)
{
	dnssec_key_t *key = NULL;
	int ret = dnssec_key_new(&key);
	if (ret != DNSSEC_EOK) {
		return kr_error(ENOMEM);
	}
	/* Create DS from DNSKEY and reinsert */
	const dnssec_binary_t key_data = { .size = rdlen, .data = (uint8_t *)rdata };
	ret = dnssec_key_set_rdata(key, &key_data);
	if (ret == DNSSEC_EOK) {
		/* Accept only KSK (257) to TA store */
		if (dnssec_key_get_flags(key) == 257)  {
			ret = dnssec_key_set_dname(key, owner);
		} else {
			ret = DNSSEC_EINVAL;
		}
		if (ret == DNSSEC_EOK) {
			ret = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA256, dst);
		}
	}
	dnssec_key_free(key);
	/* Pick some sane error code */
	if (ret != DNSSEC_EOK) {
		return kr_error(ENOMEM);
	}
	return kr_ok();
}

/* @internal Insert new TA to trust anchor set, rdata MUST be of DS type. */
static int insert_ta(map_t *trust_anchors, const knot_dname_t *name,
                     uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
	bool is_new_key = false;
	knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, name);
	if (!ta_rr) {
		ta_rr = knot_rrset_new(name, KNOT_RRTYPE_DS, KNOT_CLASS_IN, NULL);
		is_new_key = true;
	}
	/* Merge-in new key data */
	if (!ta_rr || (rdlen > 0 && knot_rrset_add_rdata(ta_rr, rdata, rdlen, ttl, NULL) != 0)) {
		knot_rrset_free(&ta_rr, NULL);
		return kr_error(ENOMEM);
	}
	if(VERBOSE_STATUS) {
		auto_free char *rr_text = kr_rrset_text(ta_rr);
		kr_log_verbose("[ ta ] new state of trust anchors for a domain: %s\n", rr_text);
	}
	if (is_new_key) {
		return map_set(trust_anchors, (const char *)name, ta_rr);
	}
	return kr_ok();
}

int kr_ta_add(map_t *trust_anchors, const knot_dname_t *name, uint16_t type,
              uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
	if (!trust_anchors || !name) {
		return kr_error(EINVAL);
	}

	/* DS/DNSEY types are accepted, for DNSKEY we
	 * need to compute a DS digest. */
	if (type == KNOT_RRTYPE_DS) {
		return insert_ta(trust_anchors, name, ttl, rdata, rdlen);
	} else if (type == KNOT_RRTYPE_DNSKEY) {
		dnssec_binary_t ds_rdata = { 0, };
		int ret = dnskey2ds(&ds_rdata, name, rdata, rdlen);
		if (ret != 0) {
			return ret;
		}
		ret = insert_ta(trust_anchors, name, ttl, ds_rdata.data, ds_rdata.size);
		dnssec_binary_free(&ds_rdata);
		return ret;
	} else { /* Invalid type for TA */
		return kr_error(EINVAL);
	}
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

bool kr_ta_covers_qry(struct kr_context *ctx, const knot_dname_t *name,
		      const uint16_t type)
{
	assert(ctx && name);
	if (type == KNOT_RRTYPE_DS && name[0] != '\0') {
		/* DS is parent-side record, so the parent name needs to be covered. */
		name = knot_wire_next_label(name, NULL);
		if (!name) {
			assert(false);
			return false;
		}
	}
	return kr_ta_covers(&ctx->trust_anchors, name)
		&& !kr_ta_covers(&ctx->negative_anchors, name);
}

/* Delete record data */
static int del_record(const char *k, void *v, void *ext)
{
	knot_rrset_t *ta_rr = v;
	if (ta_rr) {
		knot_rrset_free(&ta_rr, NULL);
	}
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
