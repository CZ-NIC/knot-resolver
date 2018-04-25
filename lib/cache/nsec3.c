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

