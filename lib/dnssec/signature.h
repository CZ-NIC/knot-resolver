/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libdnssec/key.h>
#include <libknot/rrset.h>

/**
 * Performs referral authentication according to RFC4035 5.2, bullet 2
 * @param ref Referral RRSet. Currently only DS can be used.
 * @param key Already parsed key.
 * @return    0 or error code.  In particular: DNSSEC_INVALID_DS_ALGORITHM
 *            in case *all* DSs in ref use an unimplemented algorithm.
 */
int kr_authenticate_referral(const knot_rrset_t *ref, const dnssec_key_t *key);

/**
 * Check the signature of the supplied RRSet.
 * @param rrsig       RRSet containing signatures.
 * @param key         Key to be used to validate the signature.
 * @param covered     The covered RRSet.
 * @param trim_labels Number of the leftmost labels to be removed and replaced with '*.'.
 * @return            0 if signature valid, error code else.
 */
int kr_check_signature(const knot_rdata_t *rrsig,
                       const dnssec_key_t *key, const knot_rrset_t *covered,
                       int trim_labels);
