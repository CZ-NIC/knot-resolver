/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <libknot/packet/pkt.h>

#include "lib/cookies/alg_containers.h"
#include "lib/cookies/control.h"
#include "lib/cookies/lru_cache.h"
#include "lib/cookies/nonce.h"
#include "lib/defines.h"
#include "lib/resolve.h"

/**
 * @brief Updates DNS cookie in the request EDNS options.
 * @note This function must be called before the request packet is finalised.
 * @param clnt_comp    client cookie control structure
 * @param cookie_cache cookie cache
 * @param clnt_sa      client socket address
 * @param srvr_sa      server socket address
 * @param req          name resolution request
 * @return kr_ok() or error code
 */
KR_EXPORT
int kr_request_put_cookie(const struct kr_cookie_comp *clnt_comp,
                          kr_cookie_lru_t *cookie_cache,
                          const struct sockaddr *clnt_sa,
                          const struct sockaddr *srvr_sa,
                          struct kr_request *req);

/**
 * @brief Inserts a cookie option into the OPT RR. It does not write any
 *        wire data.
 * @note The content of @a sc_input is modified. Any pre-set nonce value is
 *       ignored. After retuning its nonce value will be null.
 * @param sc_input  data needed to compute server cookie, nonce is ignored
 * @param nonce     nonce value that is actually used
 * @param alg       hash algorithm
 * @param pkt       DNS response packet
 */
KR_EXPORT
int kr_answer_write_cookie(struct knot_sc_input *sc_input,
                           const struct kr_nonce_input *nonce,
                           const struct knot_sc_alg *alg, knot_pkt_t *pkt);

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
