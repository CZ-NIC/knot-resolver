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
#include "lib/dnssec/nsec.h"

knot_db_val_t key_NSEC3(struct key *k, const knot_dname_t *name, const knot_rdata_t *nsec3param)
{
	// XXX are wildcard labels added before hashing??? + FIXME everything

	/* we basically need dname_lf with two bytes added
	 * on a correct place within the name (the cut) */
	int ret;
	const bool ok = k && name
		&& !(ret = kr_dname_lf(k->buf, k->zname, false));
	if (!ok) {
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}

	uint8_t *begin = k->buf + 1 + k->zlf_len; /* one byte after zone's zero */
	uint8_t *end = k->buf + 1 + k->buf[0]; /* we don't use the final zero in key,
						* but move it anyway */
	if (end < begin) {
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}
	int key_len;
	if (end > begin) {
		memmove(begin + 2, begin, end - begin);
		key_len = k->buf[0] + 1;
	} else {
		key_len = k->buf[0] + 2;
	}
	/* CACHE_KEY_DEF: key == zone's dname_lf + '\0' + '3' + NSEC3 hash (binary!)
	 * Iff the latter is empty, there's no zero to cut and thus the key_len difference.
	 */
	begin[0] = 0;
	begin[1] = '3'; /* tag for NSEC3 */
	k->type = KNOT_RRTYPE_NSEC3;

	/*
	VERBOSE_MSG(NULL, "<> key_NSEC1; name: ");
	kr_dname_print(name, add_wildcard ? "*." : "" , " ");
	kr_log_verbose("(zone name LF length: %d; total key length: %d)\n",
			k->zlf_len, key_len);
	*/

	return (knot_db_val_t){ k->buf + 1, key_len };
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

	assert(false);
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

	assert(false);
	return -ENOSYS;
}

