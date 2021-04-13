/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/packet/pkt.h>

#include "lib/utils.h"


/**
 * Check bitmap that child names are contained in the same zone.
 * @note see RFC6840 4.1.
 * @param bm      Bitmap from NSEC or NSEC3.
 * @param bm_size Bitmap size.
 * @return 0 if they are, >0 if not (abs(ENOENT)), <0 on error.
 */
int kr_nsec_children_in_zone_check(const uint8_t *bm, uint16_t bm_size);

/**
 * Check an NSEC or NSEC3 bitmap for NODATA for a type.
 * @param bm      Bitmap.
 * @param bm_size Bitmap size.
 * @param type    RR type to check.
 * @param owner   NSEC record owner.
 * @note This includes special checks for zone cuts, e.g. from RFC 6840 sec. 4.
 * @return 0, abs(ENOENT) (no proof), kr_error(EINVAL)
 */
int kr_nsec_bitmap_nodata_check(const uint8_t *bm, uint16_t bm_size, uint16_t type, const knot_dname_t *owner);

/**
 * Name error response check (RFC4035 3.1.3.2; RFC4035 5.4, bullet 2).
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @return           0 or error code.
 */
int kr_nsec_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                      const knot_dname_t *sname);

/**
 * No data response check (RFC4035 3.1.3.1; RFC4035 5.4, bullet 1).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @param stype      Type to be checked.
 * @return           0 or error code.
 */
int kr_nsec_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                   const knot_dname_t *sname, uint16_t stype);

/**
 * Wildcard answer response check (RFC4035 3.1.3.3).
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Name to be checked.
 * @return           0 or error code.
 */
int kr_nsec_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                           const knot_dname_t *sname);

/**
 * Authenticated denial of existence according to RFC4035 5.4.
 * @note No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @param section_id Packet section to be processed.
 * @param sname      Queried domain name.
 * @param stype      Queried type.
 * @return           0 or error code.
 */
int kr_nsec_existence_denial(const knot_pkt_t *pkt, knot_section_t section_id,
                             const knot_dname_t *sname, uint16_t stype);

/**
 * Referral to unsigned subzone check (RFC4035 5.2).
 * @note 	     No RRSIGs are validated.
 * @param pkt        Packet structure to be processed.
 * @return           0 or error code:
 * 		     DNSSEC_NOT_FOUND - neither ds nor nsec records
 *		     were not found.
 *		     EEXIST - ds record was found.
 *		     EINVAL - bogus.
 */
int kr_nsec_ref_to_unsigned(const knot_pkt_t *pkt);

/**
 * Checks whether supplied NSEC RR matches the supplied name and type.
 * @param nsec  NSEC RR.
 * @param name  Name to be checked.
 * @param type  Type to be checked.  Only use with NS!  TODO (+copy&paste NSEC3)
 * @return      0 or error code.
 */
int kr_nsec_matches_name_and_type(const knot_rrset_t *nsec,
				   const knot_dname_t *name, uint16_t type);
