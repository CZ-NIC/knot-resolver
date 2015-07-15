/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <dnssec/binary.h>
#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/key.h>
#include <libknot/descriptor.h>
#include <libknot/rdataset.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/dnskey.h>


#include "lib/defines.h"
#include "lib/dnssec.h"

#define DEBUG_MSG(fmt...) fprintf(stderr, fmt)

void kr_crypto_init(void)
{
	dnssec_crypto_init();
}

void kr_crypto_cleanup(void)
{
	dnssec_crypto_cleanup();
}

void kr_crypto_reinit(void)
{
	dnssec_crypto_reinit();
}

static inline
uint16_t _knot_ds_ktag(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return wire_read_u16(knot_rdata_offset(rrs, pos, 0));
}

static inline
uint8_t _knot_ds_alg(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 2);
}

static inline
uint8_t _knot_ds_dtype(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 3);
}

static inline
void _knot_ds_digest(const knot_rdataset_t *rrs, size_t pos,
                    uint8_t **digest, uint16_t *digest_size)
{
	KNOT_RDATASET_CHECK(rrs, pos, return);
	*digest = knot_rdata_offset(rrs, pos, 4);
	const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	*digest_size = knot_rdata_rdlen(rr) - 4;
}

/* RFC4035 5.2, second bullet */
static int authenticate_referral(const knot_rdata_t *krdata, const knot_dname_t *kown,
                                 const knot_rrset_t *ds)
{
	assert(krdata && kown && ds);
	assert(ds->type == KNOT_RRTYPE_DS);

	int ret = 0;
	dnssec_binary_t orig_ds_rdata;
	dnssec_binary_t generated_ds_rdata = {0, };
	dnssec_key_t *key = NULL;

	{
		/* Obtain RDATA of the supplied DS. */
		const knot_rdata_t *rr = knot_rdataset_at(&ds->rrs, 0);
		orig_ds_rdata.size = knot_rdata_rdlen(rr);
		orig_ds_rdata.data = knot_rdata_data(rr);
	}

	/* Set-up DNSKEY. */
	ret = dnssec_key_new(&key);
	if (ret != DNSSEC_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}
	{
		dnssec_binary_t binary_key;
		binary_key.size = knot_rdata_rdlen(krdata);
		binary_key.data = knot_rdata_data(krdata);
		if (!binary_key.size || !binary_key.data) {
			ret = kr_error(KNOT_DNSSEC_ENOKEY);
			goto fail;
		}
		ret = dnssec_key_set_rdata(key, &binary_key);
		if (ret != DNSSEC_EOK) {
			ret = kr_error(ENOMEM);
			goto fail;
		}
	}
	ret = dnssec_key_set_dname(key, kown);
	if (ret != DNSSEC_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	/* Compute DS RDATA from the DNSKEY. */
	ret = dnssec_key_create_ds(key, _knot_ds_dtype(&ds->rrs, 0), &generated_ds_rdata);
	if (ret != DNSSEC_EOK) {
		ret = kr_error(ENOMEM);
		goto fail;
	}

	/* DS records contain algorithm, key tag and the digest.
	 * Therefore the comparison of the two DS is sufficient.
	 */
	ret = ((orig_ds_rdata.size == generated_ds_rdata.size) &&
	    (memcmp(orig_ds_rdata.data, generated_ds_rdata.data, orig_ds_rdata.size) == 0)) ? kr_ok() : kr_error(KNOT_DNSSEC_ENOKEY);

fail:
	dnssec_binary_free(&generated_ds_rdata);
	dnssec_key_free(key);
	return ret;
}

int kr_dnskey_trusted(const knot_pktsection_t *sec, const knot_rrset_t *keys, const knot_rrset_t *ta)
{
	if (!sec || !keys || !ta) {
		return kr_error(EINVAL);
	}

#warning TODO: there should be an error saying that there is no matching key
	int ret = kr_error(KNOT_DNSSEC_ENOKEY);

	/* The supplied DS record has been authenticated.
	 * It has been validated or is part of a configured trust anchor.
	 *
	 * This implementation actually ignores the SEP flag.
	 */

	for (uint16_t i = 0; i < keys->rrs.rr_count; ++i) {
		const knot_rdata_t *krr = knot_rdataset_at(&keys->rrs, i);
		if (authenticate_referral(krr, keys->owner, ta) != 0) {
			continue;
		}
#warning TODO: Check the signature of the rrset.
		ret = kr_ok();
	}

	if (ret != 0) {
		return ret;
	}

	return kr_error(ENOSYS);
}
