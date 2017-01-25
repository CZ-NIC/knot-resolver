/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <dnssec/key.h>
#include <libknot/rrset.h>

/**
 * Performs referral authentication according to RFC4035 5.2, bullet 2
 * @param ref Referral RRSet. Currently only DS can be used.
 * @param key Already parsed key.
 * @return    0 or error code.
 */
int kr_authenticate_referral(const knot_rrset_t *ref, const dnssec_key_t *key);

/**
 * Check the signature of the supplied RRSet.
 * @param rrsigs      RRSet containing signatures.
 * @param pos         Index of the signature record in the signature RRSet.
 * @param key         Key to be used to validate the signature.
 * @param covered     The covered RRSet.
 * @param trim_labels Number of the leftmost labels to be removed and replaced with '*.'.
 * @return            0 if signature valid, error code else.
 */
int kr_check_signature(const knot_rrset_t *rrsigs, size_t pos,
                       const dnssec_key_t *key, const knot_rrset_t *covered,
                       int trim_labels);
