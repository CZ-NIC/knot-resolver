/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <contrib/cleanup.h>
#include <libknot/descriptor.h>
#include <libknot/rdataset.h>
#include <libknot/rrset.h>
#include <libknot/packet/wire.h>
#include <libdnssec/key.h>
#include <libdnssec/error.h>

#include "lib/defines.h"
#include "lib/dnssec.h"
#include "lib/dnssec/ta.h"
#include "lib/resolve.h"
#include "lib/utils.h"

knot_rrset_t *kr_ta_get(trie_t *trust_anchors, const knot_dname_t *name)
{
	trie_val_t *val = trie_get_try(trust_anchors, (const char *)name, strlen((const char *)name));
	return (val) ? *val : NULL;
}

const knot_dname_t * kr_ta_closest(const struct kr_context *ctx, const knot_dname_t *name,
				   const uint16_t type)
{
	kr_require(ctx && name);
	if (type == KNOT_RRTYPE_DS && name[0] != '\0') {
		/* DS is parent-side record, so the parent name needs to be covered. */
		name = knot_wire_next_label(name, NULL);
	}
	while (name) {
		struct kr_context *ctx_nc = (struct kr_context *)/*const-cast*/ctx;
		if (kr_ta_get(ctx_nc->trust_anchors, name)) {
			return name;
		}
		if (kr_ta_get(ctx_nc->negative_anchors, name)) {
			return NULL;
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
	if (ret) goto cleanup;
	/* Create DS from DNSKEY and reinsert */
	const dnssec_binary_t key_data = { .size = rdlen, .data = (uint8_t *)rdata };
	ret = dnssec_key_set_rdata(key, &key_data);
	if (ret) goto cleanup;
	/* Accept only keys with Zone and SEP flags that aren't revoked,
	 * as a precaution.  RFC 5011 also utilizes these flags.
	 * TODO: kr_dnssec_key_* names are confusing. */
	const bool flags_ok = kr_dnssec_key_zsk(rdata) && !kr_dnssec_key_revoked(rdata);
	if (!flags_ok) {
		auto_free char *owner_str = kr_dname_text(owner);
		kr_log_error(TA, "refusing to trust %s DNSKEY because of flags %d\n",
			owner_str, dnssec_key_get_flags(key));
		ret = kr_error(EILSEQ);
		goto cleanup;
	} else if (!kr_dnssec_key_ksk(rdata)) {
		auto_free char *owner_str = kr_dname_text(owner);
		int flags = dnssec_key_get_flags(key);
		kr_log_warning(TA, "warning: %s DNSKEY is missing the SEP bit; "
			"flags %d instead of %d\n",
			owner_str, flags, flags + 1/*a little ugly*/);
	}
	ret = dnssec_key_set_dname(key, owner);
	if (ret) goto cleanup;
	ret = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA256, dst);
cleanup:
	dnssec_key_free(key);
	return kr_error(ret);
}

/* @internal Insert new TA to trust anchor set, rdata MUST be of DS type. */
static int insert_ta(trie_t *trust_anchors, const knot_dname_t *name,
                     uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
	bool is_new_key = false;
	knot_rrset_t *ta_rr = kr_ta_get(trust_anchors, name);
	if (!ta_rr) {
		ta_rr = knot_rrset_new(name, KNOT_RRTYPE_DS, KNOT_CLASS_IN, ttl, NULL);
		is_new_key = true;
	}
	/* Merge-in new key data */
	if (!ta_rr || (rdlen > 0 && knot_rrset_add_rdata(ta_rr, rdata, rdlen, NULL) != 0)) {
		knot_rrset_free(ta_rr, NULL);
		return kr_error(ENOMEM);
	}
	if (is_new_key) {
		trie_val_t *val = trie_get_ins(trust_anchors, (const char *)name, strlen((const char *)name));
		if (kr_fails_assert(val))
			return kr_error(EINVAL);
		*val = ta_rr;
	}
	return kr_ok();
}

int kr_ta_add(trie_t *trust_anchors, const knot_dname_t *name, uint16_t type,
              uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
	if (!trust_anchors || !name) {
		return kr_error(EINVAL);
	}

	/* DS/DNSKEY types are accepted, for DNSKEY we
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

/* Delete record data */
static int del_record(trie_val_t *v, void *ext)
{
	knot_rrset_t *ta_rr = *v;
	if (ta_rr) {
		knot_rrset_free(ta_rr, NULL);
	}
	return 0;
}

int kr_ta_del(trie_t *trust_anchors, const knot_dname_t *name)
{
	knot_rrset_t *ta_rr;
	int ret = trie_del(trust_anchors, (const char *)name, strlen((const char *)name),
			(trie_val_t *) &ta_rr);
	if (ret == KNOT_EOK && ta_rr)
		knot_rrset_free(ta_rr, NULL);
	return kr_ok();
}

void kr_ta_clear(trie_t *trust_anchors)
{
	trie_apply(trust_anchors, del_record, NULL);
	trie_clear(trust_anchors);
}
