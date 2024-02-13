/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/packet/pkt.h>
#include <libknot/rrtype/nsec3.h>
#include <libdnssec/nsec.h>


static inline unsigned int kr_nsec3_price(unsigned int iterations, unsigned int salt_len)
{
	// SHA1 works on 64-byte chunks.
	// On iterating we hash the salt + 20 bytes of the previous hash.
	int chunks_per_iter = (20 + salt_len - 1) / 64 + 1;
	return (iterations + 1) * chunks_per_iter;
}

/** High numbers in NSEC3 iterations don't really help security
 *
 * ...so we avoid doing all the work.  The limit is a current compromise;
 * answers using NSEC3 over kr_nsec3_limited* get downgraded to insecure status.
 *
   https://datatracker.ietf.org/doc/html/rfc9276#name-recommendation-for-validati
 */
static inline bool kr_nsec3_limited(unsigned int iterations, unsigned int salt_len)
{
	const int MAX_ITERATIONS = 50; // limit with short salt length
	return kr_nsec3_price(iterations, salt_len) > MAX_ITERATIONS + 1;
}
static inline bool kr_nsec3_limited_rdata(const knot_rdata_t *rd)
{
	return kr_nsec3_limited(knot_nsec3_iters(rd), knot_nsec3_salt_len(rd));
}
static inline bool kr_nsec3_limited_params(const dnssec_nsec3_params_t *params)
{
	return kr_nsec3_limited(params->iterations, params->salt.size);
}

/** Return limit on NSEC3 depth.  The point is to avoid doing too much work on SHA1.
 *
 * CVE-2023-50868: NSEC3 closest encloser proof can exhaust CPU
 *
 * 128 is chosen so that zones with good NSEC3 parameters (giving _price() == 1)
 * won't be limited in any way.  Performance doesn't seem too bad with that either.
 */
static inline int kr_nsec3_max_depth(const dnssec_nsec3_params_t *params)
{
	return 128 / kr_nsec3_price(params->iterations, params->salt.size);
}


/**
 * Name error response check (RFC5155 7.2.2).
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @return           0 or error code.
 */
int kr_nsec3_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                       const knot_dname_t *sname);

/**
 * Wildcard answer response check (RFC5155 7.2.6).
 * @param pkt          Packet structure to be processed.
 * @param section_id   Packet section to be processed.
 * @param sname        Name to be checked.
 * @param trim_to_next Number of labels to remove to obtain next closer name.
 * @return             0 or error code:
 *                     KNOT_ERANGE - NSEC3 RR that covers a wildcard
 *                     has been found, but has opt-out flag set;
 *                     otherwise - error.
 * Too expensive NSEC3 records are skipped, so you probably get kr_error(ENOENT).
 */
int kr_nsec3_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                            const knot_dname_t *sname, int trim_to_next);

/**
 * Authenticated denial of existence according to RFC5155 8.5 and 8.7.
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Queried domain name.
 * @param stype      Queried type.
 * @return           0 or error code:
 *                   DNSSEC_NOT_FOUND - neither ds nor nsec records
 *                   were not found.
 *                   KNOT_ERANGE - denial of existence can't be proven
 *                   due to opt-out, otherwise - bogus.
 */
int kr_nsec3_no_data(const knot_pkt_t *pkt, knot_section_t section_id,
                     const knot_dname_t *sname, uint16_t stype);

/**
 * Referral to unsigned subzone check (RFC5155 8.9).
 * @note 	     No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @return           0 or error code:
 *                   KNOT_ERANGE - denial of existence can't be proven
 *                   due to opt-out.
 *                   EEXIST - ds record was found.
 *                   EINVAL - bogus.
 */
int kr_nsec3_ref_to_unsigned(const knot_pkt_t *pkt);

/**
 * Checks whether supplied NSEC3 RR matches the supplied name and NS type.
 * @param nsec3 NSEC3 RR.
 * @param name  Name to be checked.
 * @param type  Type to be checked.  Only use with NS!  TODO
 * @return      0 or error code.
 */
int kr_nsec3_matches_name_and_type(const knot_rrset_t *nsec3,
				   const knot_dname_t *name, uint16_t type);
