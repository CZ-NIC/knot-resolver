/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/** @file
 * Implementation of NSEC3 handling.  Prototypes in ./impl.h
 */

#include "lib/cache/impl.h"

#include "contrib/base32hex.h"
#include <dnssec/error.h>
#include <dnssec/nsec.h>

static const knot_db_val_t VAL_EMPTY = { NULL, 0 };

/** Common part: write all but the NSEC3 hash. */
static knot_db_val_t key_NSEC3_common(struct key *k, const knot_dname_t *zname,
					const nsec_p_hash_t nsec_p_hash)
{
	int ret;
	const bool ok = k && zname
		&& !(ret = kr_dname_lf(k->buf, zname, false));
	if (!ok) {
		assert(false);
		return VAL_EMPTY;
	}

	/* CACHE_KEY_DEF: key == zone's dname_lf + '\0' + '3' + nsec_p hash (4B)
	 * 			+ NSEC3 hash (20B binary!)
	 * LATER(optim.) nsec_p hash: perhaps 2B would give a sufficient probability
	 * of avoiding collisions.
	 */
	uint8_t *begin = k->buf + 1 + k->zlf_len; /* one byte after zone's zero */
	begin[0] = 0;
	begin[1] = '3'; /* tag for NSEC3 */
	k->type = KNOT_RRTYPE_NSEC3;
	memcpy(begin + 2, &nsec_p_hash, sizeof(nsec_p_hash));
	return (knot_db_val_t){
		.data = k->buf + 1,
		.len = begin + 2 + sizeof(nsec_p_hash) - (k->buf + 1),
	};
}

knot_db_val_t key_NSEC3(struct key *k, const knot_dname_t *nsec3_name,
			const nsec_p_hash_t nsec_p_hash)
{
	knot_db_val_t val = key_NSEC3_common(k, nsec3_name /*only zname required*/,
						nsec_p_hash);
	if (!val.data) return val;
	int len = base32hex_decode(nsec3_name + 1, nsec3_name[0], val.data + val.len,
				   KR_CACHE_KEY_MAXLEN - val.len);
	if (len != 20) {
		assert(false); // FIXME: just debug, possible bogus input in real life
		return VAL_EMPTY;
	}
	val.len += len;
	return val;
}

/** Construct a string key for for NSEC3 predecessor-search, from an non-NSEC3 name.
 * \note k->zlf_len and k->zname are assumed to have been correctly set */
static knot_db_val_t key_NSEC3_name(struct key *k, const knot_dname_t *name,
		const bool add_wildcard,
		const nsec_p_hash_t nsec_p_hash, const uint8_t *nsec_p)
{
	knot_db_val_t val = key_NSEC3_common(k, k->zname, nsec_p_hash);
	const bool ok = val.data && nsec_p;
	if (!ok) return VAL_EMPTY;

	/* Make `name` point to correctly wildcarded owner name. */
	uint8_t buf[KNOT_DNAME_MAXLEN];
	int name_len;
	if (add_wildcard) {
		buf[0] = '\1';
		buf[1] = '*';
		name_len = knot_dname_to_wire(buf + 2, name, sizeof(buf) - 2);
		if (name_len < 0) return VAL_EMPTY; /* wants wildcard but doesn't fit */
		name = buf;
	} else {
		name_len = knot_dname_size(name);
	}
	/* Append the NSEC3 hash. */
	dnssec_nsec3_params_t params;
	{
		const dnssec_binary_t rdata = {
			.size = nsec_p_rdlen(nsec_p),
			.data = (uint8_t *)/*const-cast*/nsec_p,
		};
		int ret = dnssec_nsec3_params_from_rdata(&params, &rdata);
		if (ret != DNSSEC_EOK) return VAL_EMPTY;
	}
	const dnssec_binary_t dname = {
		.size = knot_dname_size(name),
		.data = (uint8_t *)/*const-cast*/name,
	};
	dnssec_binary_t hash = {
		.size = KR_CACHE_KEY_MAXLEN - val.len,
		.data = val.data + val.len,
	};
		/* FIXME: vv this requires a patched libdnssec - tries to realloc() */
	int ret = dnssec_nsec3_hash(&dname, &params, &hash);
	if (ret != DNSSEC_EOK) return VAL_EMPTY;
	val.len += hash.size;
	return val;
}

int nsec3_encloser(struct key *k, struct answer *ans,
		   const int sname_labels, int *clencl_labels,
		   knot_db_val_t *cover_low_kwz, knot_db_val_t *cover_hi_kwz,
		   const struct kr_query *qry, struct kr_cache *cache)
{
	/* Basic sanity check. */
	const bool ok = k && ans && clencl_labels && cover_low_kwz && cover_hi_kwz
			&& qry && cache;
	if (!ok) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	// FIXME get *nsec_p - possibly just add to the parameter list

	/*** Find and cover the next closer name - cycle: name starting at sname,
	 * proceeding while longer than zname, shortening by one label on step.
	 * Each iteration: */
		/*** 1. compute NSEC3 hash of the name with nsec_p. */
		/*** 2. find a previous-or-equal NSEC3 in cache covering the name,
		 * checking TTL etc.
		 * Exit if match is found (may have NODATA proof if the first iteration),
		 * break if cover is found. */

	/*** One more step but searching for match this time
	 * - that's the closest (provable) encloser. */

	//assert(false);
	return -ENOSYS;
}

int nsec3_src_synth(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    knot_db_val_t cover_low_kwz, knot_db_val_t cover_hi_kwz,
		    const struct kr_query *qry, struct kr_cache *cache)
{
	/* Construct key for the source of synthesis.
	 *
	 * It's possible that all that follows in this function might be
	 * completely the same as for NSEC -> probably some code sharing. */

	/* Check if our covering NSEC3 also covers/matches SS (and exit).
	 * That's unlikely except in tiny zones, but we want to avoid
	 * duplicities in answer anyway. */

	/* Find the NSEC3 in cache (or exit). */

	/* Handle the two cases: covered and matched. */

	//assert(false);
	return -ENOSYS;
}

