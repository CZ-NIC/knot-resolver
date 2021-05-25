/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

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
	if (kr_fails_assert(cache && sa && cc && cc_len))
		return NULL;

	const uint8_t *cached_opt = kr_cookie_lru_get(cache, sa);
	if (!cached_opt)
		return NULL;

	const uint8_t *cached_cc = knot_edns_opt_get_data((uint8_t *) cached_opt);

	if (cc_len == KNOT_OPT_COOKIE_CLNT &&
	    0 == memcmp(cc, cached_cc, cc_len)) {
		return cached_opt;
	}

	return NULL;
}

/**
 * @brief Put a client cookie into the RR Set.
 */
static int opt_rr_put_cookie(knot_rrset_t *opt_rr, uint8_t *data,
                             uint16_t data_len, knot_mm_t *mm)
{
	if (kr_fails_assert(opt_rr && data && data_len > 0))
		return kr_error(EINVAL);

	const uint8_t *cc = NULL, *sc = NULL;
	uint16_t cc_len = 0, sc_len = 0;

	int ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len,
	                                     &sc, &sc_len);
	if (ret != KNOT_EOK)
		return kr_error(EINVAL);
	if (kr_fails_assert(data_len == cc_len + sc_len))
		return kr_error(EINVAL);

	uint16_t cookies_size = data_len;
	uint8_t *cookies_data = NULL;

	ret = knot_edns_reserve_unique_option(opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                      cookies_size, &cookies_data, mm);
	if (ret != KNOT_EOK)
		return kr_error(EINVAL);
	if (kr_fails_assert(cookies_data))
		return kr_error(EINVAL);

	cookies_size = knot_edns_opt_cookie_write(cc, cc_len, sc, sc_len,
	                                          cookies_data, cookies_size);
	if (cookies_size == 0)
		return kr_error(EINVAL);
	if (kr_fails_assert(cookies_size == data_len))
		return kr_error(EINVAL);

	return kr_ok();
}

/**
 * @brief Puts entire EDNS option into the RR Set.
 */
static int opt_rr_put_cookie_opt(knot_rrset_t *opt_rr, uint8_t *option, knot_mm_t *mm)
{
	if (kr_fails_assert(opt_rr && option))
		return kr_error(EINVAL);

	uint16_t opt_code = knot_edns_opt_get_code(option);
	if (opt_code != KNOT_EDNS_OPTION_COOKIE)
		return kr_error(EINVAL);

	uint16_t opt_len = knot_edns_opt_get_length(option);
	uint8_t *opt_data = knot_edns_opt_get_data(option);
	if (!opt_data || opt_len == 0)
		return kr_error(EINVAL);

	return opt_rr_put_cookie(opt_rr, opt_data, opt_len, mm);
}

int kr_request_put_cookie(const struct kr_cookie_comp *clnt_comp,
                          kr_cookie_lru_t *cookie_cache,
                          const struct sockaddr *clnt_sa,
                          const struct sockaddr *srvr_sa,
                          struct kr_request *req)
{
	if (!clnt_comp || !req)
		return kr_error(EINVAL);

	if (!req->ctx->opt_rr)
		return kr_ok();

	if (!clnt_comp->secr || (clnt_comp->alg_id < 0) || !cookie_cache)
		return kr_error(EINVAL);

	/*
	 * Generate client cookie from client address, server address and
	 * secret quantity.
	 */
	struct knot_cc_input input = {
		.clnt_sockaddr = clnt_sa,
		.srvr_sockaddr = srvr_sa,
		.secret_data = clnt_comp->secr->data,
		.secret_len = clnt_comp->secr->size
	};
	uint8_t cc[KNOT_OPT_COOKIE_CLNT];
	uint16_t cc_len = KNOT_OPT_COOKIE_CLNT;
	const struct knot_cc_alg *cc_alg = kr_cc_alg_get(clnt_comp->alg_id);
	if (!cc_alg)
		return kr_error(EINVAL);
	if (kr_fails_assert(cc_alg->gen_func))
		return kr_error(EINVAL);
	cc_len = cc_alg->gen_func(&input, cc, cc_len);
	if (cc_len != KNOT_OPT_COOKIE_CLNT)
		return kr_error(EINVAL);

	const uint8_t *cached_cookie = peek_and_check_cc(cookie_cache,
	                                                 srvr_sa, cc, cc_len);

	/* Add cookie option. */
	int ret;
	if (cached_cookie) {
		ret = opt_rr_put_cookie_opt(req->ctx->opt_rr,
		                            (uint8_t *)cached_cookie,
		                            req->ctx->pool);
	} else {
		ret = opt_rr_put_cookie(req->ctx->opt_rr, cc, cc_len,
		                        req->ctx->pool);
	}

	return ret;
}

int kr_answer_write_cookie(struct knot_sc_input *sc_input,
                           const struct kr_nonce_input *nonce,
                           const struct knot_sc_alg *alg, knot_pkt_t *pkt)
{
	if (!sc_input || !sc_input->cc || sc_input->cc_len == 0)
		return kr_error(EINVAL);

	if (!sc_input->srvr_data || !sc_input->srvr_data->clnt_sockaddr ||
	    !sc_input->srvr_data->secret_data ||
	    !sc_input->srvr_data->secret_len) {
		return kr_error(EINVAL);
	}

	if (!nonce)
		return kr_error(EINVAL);

	if (!alg || !alg->hash_size || !alg->hash_func)
		return kr_error(EINVAL);

	if (!pkt || !pkt->opt_rr)
		return kr_error(EINVAL);

	uint16_t nonce_len = KR_NONCE_LEN;
	uint16_t hash_len = alg->hash_size;

	/*
	 * Space for cookie is reserved inside the EDNS OPT RR of
	 * the answer packet.
	 */
	uint8_t *cookie = NULL;
	uint16_t cookie_len = knot_edns_opt_cookie_data_len(sc_input->cc_len,
	                                                    nonce_len + hash_len);
	if (cookie_len == 0)
		return kr_error(EINVAL);

	int ret = knot_edns_reserve_unique_option(pkt->opt_rr,
	                                          KNOT_EDNS_OPTION_COOKIE,
	                                          cookie_len, &cookie,
	                                          &pkt->mm);
	if (ret != KNOT_EOK)
		return kr_error(ENOMEM);
	if (kr_fails_assert(cookie))
		return kr_error(EFAULT);

	/*
	 * Function knot_edns_opt_cookie_data_len() returns the sum of its
	 * parameters or zero. Anyway, let's check again.
	 */
	if (cookie_len < (sc_input->cc_len + nonce_len + hash_len))
		return kr_error(EINVAL);

	/* Copy client cookie data portion. */
	memcpy(cookie, sc_input->cc, sc_input->cc_len);

	if (nonce_len) {
		/* Write nonce data portion. */
		kr_nonce_write_wire(cookie + sc_input->cc_len, nonce_len,
		                    nonce);
		/* Adjust input for written nonce value. */
		sc_input->nonce = cookie + sc_input->cc_len;
		sc_input->nonce_len = nonce_len;
	}

	hash_len = alg->hash_func(sc_input,
	                          cookie + sc_input->cc_len + nonce_len,
	                          hash_len);
	/* Zero nonce values. */
	sc_input->nonce = NULL;
	sc_input->nonce_len = 0;

	return (hash_len != 0) ? kr_ok() : kr_error(EINVAL);
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

	if (!pkt || !knot_pkt_has_edns(pkt))
		return kr_error(EINVAL);

	uint8_t rcode = whole_rcode & 0x0f;
	uint8_t ext_rcode = whole_rcode >> 4;
	knot_wire_set_rcode(pkt->wire, rcode);
	knot_edns_set_ext_rcode(pkt->opt_rr, ext_rcode);

	return kr_ok();
}

uint8_t *kr_no_question_cookie_query(const knot_pkt_t *pkt)
{
	if (!pkt || knot_wire_get_qdcount(pkt->wire) > 0)
		return false;

	if (knot_wire_get_qr(pkt->wire) != 0 || !pkt->opt_rr)
		return false;

	return knot_edns_get_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE);
}

int kr_parse_cookie_opt(uint8_t *cookie_opt, struct knot_dns_cookies *cookies)
{
	if (!cookie_opt || !cookies)
		return kr_error(EINVAL);

	const uint8_t *cookie_data = knot_edns_opt_get_data(cookie_opt);
	uint16_t cookie_len = knot_edns_opt_get_length(cookie_opt);
	if (!cookie_data || cookie_len == 0)
		return kr_error(EINVAL);

	int ret =  knot_edns_opt_cookie_parse(cookie_data, cookie_len,
	                                      &cookies->cc, &cookies->cc_len,
	                                      &cookies->sc, &cookies->sc_len);

	return (ret == KNOT_EOK) ? kr_ok() : kr_error(EINVAL);
}
