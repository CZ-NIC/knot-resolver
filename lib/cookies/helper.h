/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <libknot/packet/pkt.h>

#include "lib/cookies/alg_containers.h"
#include "lib/cookies/control.h"
#include "lib/cookies/lru_cache.h"
#include "lib/cookies/nonce.h"
#include "lib/defines.h"

/**
 * @brief Insert a DNS cookie into query packet.
 * @note The packet must already contain ENDS section.
 * @param clnt_comp    client cookie control structure
 * @param cookie_cache cookie cache
 * @param clnt_sa      client socket address
 * @param srvr_sa      server socket address
 * @param pkt          DNS request packet
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_request_put_cookie(const struct kr_cookie_comp *clnt_comp,
                          kr_cookie_lru_t *cookie_cache,
                          const struct sockaddr *clnt_sa,
                          const struct sockaddr *srvr_sa,
                          knot_pkt_t *pkt);

/**
 * @brief Inserts a cookie option into the OPT RR. It does not write any
 *        wire data.
 * @param srvr_data server knowledge
 * @param cc        client cookie
 * @param cc_len    client cookie length
 * @param nonce     nonce value
 * @param alg       hash algorithm
 * @param pkt       DNS response packet
 */
KR_EXPORT
int kr_answer_write_cookie(const struct knot_sc_private *srvr_data,
                           const uint8_t *cc, uint16_t cc_len,
                           struct kr_nonce_input *nonce,
                           const struct knot_sc_alg *alg,
                           knot_pkt_t *pkt);

/**
 * @brief Set RCODE and extended RCODE.
 * @param pkt DNS packet
 * @param whole_rcode RCODE value
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_pkt_set_ext_rcode(knot_pkt_t *pkt, uint16_t whole_rcode);

/**
 * @brief Check whether packet is a server cookie request according to
 *        RFC7873 5.4.
 * @param pkt Packet to be examined.
 * @return Pointer to entire cookie option if is a server cookie query, NULL on
 *         errors or if packet doesn't contain cookies or if QDCOUNT > 0.
 */
KR_EXPORT
uint8_t *kr_no_question_cookie_query(const knot_pkt_t *pkt);

/**
 * @brief Parse cookies from cookie option.
 * @param cookie_opt Cookie option.
 * @param cookies    Cookie structure to be set.
 * @return kr_ok() on success, error if cookies are malformed.
 */
KR_EXPORT
int kr_parse_cookie_opt(uint8_t *cookie_opt, struct knot_dns_cookies *cookies);
