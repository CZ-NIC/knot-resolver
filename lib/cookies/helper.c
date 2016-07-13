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

#include <assert.h>
#include <libknot/rrtype/opt.h>
#include <libknot/rrtype/opt-cookie.h>

#include "lib/cookies/helper.h"
#include "lib/defines.h"

/**
 * @brief Check whether there is a cached cookie that matches the current
 *        client cookie.
 */
static const uint8_t *peek_and_check_cc(kr_cookie_lru_t *cache, const void *sa,
                                        const uint8_t *cc, uint16_t cc_len)
{
	assert(cache && sa && cc && cc_len);

	const uint8_t *cached_opt = kr_cookie_lru_get(cache, sa);
	if (!cached_opt) {
		return NULL;
	}

	const uint8_t *cached_cc = knot_edns_opt_get_data((uint8_t *) cached_opt);

	if (cc_len == KNOT_OPT_COOKIE_CLNT &&
	    0 == memcmp(cc, cached_cc, cc_len)) {
		return cached_opt;
	}

	return NULL;
}

/**
 * @brief Adds entire EDNS option into the RR Set.
 */
static int opt_rr_add_opt(knot_rrset_t *opt_rr, uint8_t *option, knot_mm_t *mm)
{
	assert(opt_rr && option);

	uint8_t *reserved_data = NULL;
	uint16_t opt_code = knot_edns_opt_get_code(option);
	uint16_t opt_len = knot_edns_opt_get_length(option);
	uint8_t *opt_data = knot_edns_opt_get_data(option);

	int ret = knot_edns_reserve_option(opt_rr, opt_code,
	                                   opt_len, &reserved_data, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(reserved_data);

	memcpy(reserved_data, opt_data, opt_len);
	return KNOT_EOK;
}

/**
 * @brief Add a client cookie option into the RR Set.
 */
static int opt_rr_add_cc(knot_rrset_t *opt_rr, uint8_t *cc, uint16_t cc_len,
                         knot_mm_t *mm)
{
#define SC NULL
#define SC_LEN 0
	uint16_t cookies_size = 0;
	uint8_t *cookies_data = NULL;

	cookies_size = knot_edns_opt_cookie_data_len(cc_len, SC_LEN);

	int ret = knot_edns_reserve_option(opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   cookies_size, &cookies_data, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(cookies_data != NULL);

	ret = knot_edns_opt_cookie_write(cc, cc_len, SC, SC_LEN,
	                                 cookies_data, &cookies_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(cookies_size == knot_edns_opt_cookie_data_len(cc_len, SC_LEN));

	return KNOT_EOK;
#undef SC
#undef SC_LEN
}

int kr_request_put_cookie(const struct kr_cookie_comp *clnt_comp,
                          kr_cookie_lru_t *cookie_cache,
                          const struct sockaddr *clnt_sa,
                          const struct sockaddr *srvr_sa,
                          knot_pkt_t *pkt)
{
	if (!clnt_comp || !pkt) {
		return kr_error(EINVAL);
	}

	if (!pkt->opt_rr) {
		return kr_ok();
	}

	if (!clnt_comp->secr || (clnt_comp->alg_id < 0) || !cookie_cache) {
		return kr_error(EINVAL);
	}

	/* Generate client cookie from client address, server address and
	 * secret quantity. */
	struct knot_cc_input input = {
		.clnt_sockaddr = clnt_sa,
		.srvr_sockaddr = srvr_sa,
		.secret_data = clnt_comp->secr->data,
		.secret_len = clnt_comp->secr->size
	};
	uint8_t cc[KNOT_OPT_COOKIE_CLNT];
	uint16_t cc_len = KNOT_OPT_COOKIE_CLNT;
	assert((clnt_comp->alg_id >= 0) && kr_cc_algs[clnt_comp->alg_id] &&
	       kr_cc_algs[clnt_comp->alg_id]->gen_func);
	int ret = kr_cc_algs[clnt_comp->alg_id]->gen_func(&input, cc, &cc_len);
	if (ret != kr_ok()) {
		return ret;
	}
	assert(cc_len == KNOT_OPT_COOKIE_CLNT);

	const uint8_t *cached_cookie = peek_and_check_cc(cookie_cache,
	                                                 srvr_sa, cc, cc_len);

	/* This is a very nasty hack that prevents the packet to be corrupted
	 * when using contemporary 'Cookie interface'. */
	assert(pkt->current == KNOT_ADDITIONAL);
	pkt->sections[KNOT_ADDITIONAL].count -= 1;
	pkt->rrset_count -= 1;
	pkt->size -= knot_edns_wire_size(pkt->opt_rr);
	knot_wire_set_arcount(pkt->wire, knot_wire_get_arcount(pkt->wire) - 1);

	if (cached_cookie) {
		ret = opt_rr_add_opt(pkt->opt_rr, (uint8_t *)cached_cookie,
		                     &pkt->mm);
	} else {
		ret = opt_rr_add_cc(pkt->opt_rr, cc, cc_len, &pkt->mm);
	}

	/* Write to packet. */
	return knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);
}

int kr_answer_write_cookie(const struct knot_sc_private *srvr_data,
                           const uint8_t *cc, uint16_t cc_len,
                           struct kr_nonce_input *nonce,
                           const struct knot_sc_alg *alg,
                           knot_pkt_t *pkt)
{
	if (!srvr_data || !srvr_data->clnt_sockaddr ||
	    !srvr_data->secret_data|| !srvr_data->secret_len) {
		return kr_error(EINVAL);
	}

	if (!cc || cc_len == 0 || !nonce) {
		return kr_error(EINVAL);
	}

	if (!alg || !alg->hash_size || !alg->hash_func) {
		return kr_error(EINVAL);
	}

	if (!pkt && !pkt->opt_rr) {
		return kr_error(EINVAL);
	}

	uint16_t nonce_len = NONCE_LEN;
	uint16_t hash_len = alg->hash_size;

	uint8_t *cookie = NULL;
	uint16_t cookie_len = knot_edns_opt_cookie_data_len(cc_len,
	                                                    nonce_len + hash_len);
	if (cookie_len == 0) {
		return kr_error(EINVAL);
	}

	int ret = knot_edns_reserve_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   cookie_len, &cookie, &pkt->mm);
	if (ret != KNOT_EOK) {
		return kr_error(ENOMEM);
	}

	struct knot_sc_input input = {
		.cc = cookie,
		.cc_len = cc_len,
		.srvr_data = srvr_data
	};
	memcpy(cookie, cc, cc_len);

	if (nonce_len) {
		kr_nonce_write_wire(cookie + cc_len, &nonce_len, nonce);

		input.nonce = cookie + cc_len;
		input.nonce_len = nonce_len;
	}

	ret = alg->hash_func(&input, cookie + cc_len + nonce_len, &hash_len);
	if (ret != KNOT_EOK) {
		return kr_error(EINVAL);
	}

	return kr_ok();
}

int kr_pkt_set_ext_rcode(knot_pkt_t *pkt, uint16_t whole_rcode)
{
	/*
	 * RFC6891 6.1.3 -- extended RCODE forms the upper 8 bits of whole
	 * 12-bit RCODE (together with the 4 bits of 'normal' RCODE).
	 *
	 * | 11 10 09 08 07 06 05 04 | 03 02 01 00 |
	 * |          12-bit whole RCODE           |
	 * |   8-bit extended RCODE  | 4-bit RCODE |
	 */

	if (!pkt || !knot_pkt_has_edns(pkt)) {
		return kr_error(EINVAL);
	}

	uint8_t rcode = whole_rcode & 0x0f;
	uint8_t ext_rcode = whole_rcode >> 4;
	knot_wire_set_rcode(pkt->wire, rcode);
	knot_edns_set_ext_rcode(pkt->opt_rr, ext_rcode);

	return kr_ok();
}

uint8_t *kr_no_question_cookie_query(const knot_pkt_t *pkt)
{
	if (!pkt || knot_wire_get_qdcount(pkt->wire) > 0) {
		return false;
	}

	if (knot_wire_get_qr(pkt->wire) != 0 || !pkt->opt_rr) {
		return false;
	}

	return knot_edns_get_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE);
}

int kr_parse_cookie_opt(uint8_t *cookie_opt, struct knot_dns_cookies *cookies)
{
	if (!cookie_opt || !cookies) {
		kr_error(EINVAL);
	}

	const uint8_t *cookie_data = knot_edns_opt_get_data(cookie_opt);
	uint16_t cookie_len = knot_edns_opt_get_length(cookie_opt);
	assert(cookie_data && cookie_len);

	int ret =  knot_edns_opt_cookie_parse(cookie_data, cookie_len,
	                                      &cookies->cc, &cookies->cc_len,
	                                      &cookies->sc, &cookies->sc_len);

	return (ret == KNOT_EOK) ? kr_ok() : kr_error(EINVAL);
}
