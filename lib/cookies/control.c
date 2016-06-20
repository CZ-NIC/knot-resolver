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

//#define MODULE_DEBUG_MSGS 1 /* Comment out if debug messages are not desired. */

#include <assert.h>
#include <libknot/error.h>
#include <stdint.h>
#include <string.h>

#include "lib/cookies/cache.h"
#include "lib/cookies/control.h"
#include "lib/layer.h"
#include "lib/utils.h"

#if defined(MODULE_DEBUG_MSGS)
#  define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "cookies_control",  fmt)
#else /* !defined(MODULE_DEBUG_MSGS) */
#  define DEBUG_MSG(qry, fmt...) do { } while (0)
#endif /* defined(MODULE_DEBUG_MSGS) */

struct kr_cookie_ctx kr_glob_cookie_ctx = {
	.clnt = { false, { NULL, NULL }, { NULL, NULL}, DFLT_COOKIE_TTL },
	.srvr = { false, { NULL, NULL }, { NULL, NULL} }
};

static int opt_rr_add_cookies(knot_rrset_t *opt_rr,
                              uint8_t *cc, uint16_t cc_len,
                              uint8_t *sc, uint16_t sc_len,
                              knot_mm_t *mm)
{
	uint16_t cookies_size = 0;
	uint8_t *cookies_data = NULL;

	cookies_size = knot_edns_opt_cookie_data_len(cc_len, sc_len);

	int ret = knot_edns_reserve_option(opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   cookies_size, &cookies_data, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(cookies_data != NULL);

	ret = knot_edns_opt_cookie_write(cc, cc_len, sc, sc_len,
	                                 cookies_data, &cookies_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(cookies_size == knot_edns_opt_cookie_data_len(cc_len, sc_len));

	return KNOT_EOK;
}

static int opt_rr_add_option(knot_rrset_t *opt_rr, uint8_t *option,
                             knot_mm_t *mm)
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
 * Check whether there is a cached cookie that matches the current client
 * cookie.
 */
static const uint8_t *peek_and_check_cc(struct kr_cache *cache,
                                        const void *sockaddr,
                                        const uint8_t *cc, uint16_t cc_len)
{
	assert(cache && sockaddr && cc && cc_len);

	uint32_t timestamp = 0;
	struct timed_cookie timed_cookie = { 0, };

	int ret = kr_cookie_cache_peek_cookie(cache, sockaddr, &timed_cookie,
	                                      &timestamp);
	if (ret != kr_ok()) {
		return NULL;
	}
	assert(timed_cookie.cookie_opt);

	/* Ignore the timestamp and time to leave. If the cookie is in cache
	 * then just use it. The cookie control should be prerformed in the
	 * cookie module/layer. */

	const uint8_t *cached_cc = knot_edns_opt_get_data((uint8_t *) timed_cookie.cookie_opt);

	if (cc_len == KNOT_OPT_COOKIE_CLNT &&
	    0 == memcmp(cc, cached_cc, cc_len)) {
		return timed_cookie.cookie_opt;
	}

	return NULL;
}

int kr_request_put_cookie(const struct kr_clnt_cookie_settings *clnt_cntrl,
                          struct kr_cache *cookie_cache,
                          const void *clnt_sockaddr, const void *srvr_sockaddr,
                          knot_pkt_t *pkt)
{
	if (!clnt_cntrl || !pkt) {
		return kr_error(EINVAL);
	}

	if (!pkt->opt_rr) {
		return kr_ok();
	}

	if (!clnt_cntrl->csec || !clnt_cntrl->calg ||
	    !cookie_cache) {
		return kr_error(EINVAL);
	}

	/* Generate client cookie.
	 * TODO -- generate client cookie from client address, server address
	 * and secret quantity. */
	struct kr_clnt_cookie_input input = {
		.clnt_sockaddr = clnt_sockaddr,
		.srvr_sockaddr = srvr_sockaddr,
		.secret_data = clnt_cntrl->csec->data,
		.secret_len = clnt_cntrl->csec->size
	};
	uint8_t cc[KNOT_OPT_COOKIE_CLNT];
	uint16_t cc_len = KNOT_OPT_COOKIE_CLNT;
	assert(clnt_cntrl->calg && clnt_cntrl->calg->func);
	int ret = clnt_cntrl->calg->func(&input, cc, &cc_len);
	if (ret != kr_ok()) {
		return ret;
	}
	assert(cc_len == KNOT_OPT_COOKIE_CLNT);

	const uint8_t *cached_cookie = peek_and_check_cc(cookie_cache,
	                                                 srvr_sockaddr,
	                                                 cc, cc_len);

	/* This is a very nasty hack that prevents the packet to be corrupted
	 * when using contemporary 'Cookie interface'. */
	assert(pkt->current == KNOT_ADDITIONAL);
	pkt->sections[KNOT_ADDITIONAL].count -= 1;
	pkt->rrset_count -= 1;
	pkt->size -= knot_edns_wire_size(pkt->opt_rr);
	knot_wire_set_arcount(pkt->wire, knot_wire_get_arcount(pkt->wire) - 1);
#if 0
	/* Reclaim reserved size -- does not work as intended.. */
	ret = knot_pkt_reclaim(pkt, knot_edns_wire_size(pkt->opt_rr));
	if (ret != KNOT_EOK) {
		return ret;
	}
#endif

	if (cached_cookie) {
		ret = opt_rr_add_option(pkt->opt_rr, (uint8_t *) cached_cookie,
		                        &pkt->mm);
	} else {
		ret = opt_rr_add_cookies(pkt->opt_rr, cc, cc_len,
		                         NULL, 0, &pkt->mm);
	}

	/* Write to packet. */
	assert(pkt->current == KNOT_ADDITIONAL);
	return knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, pkt->opt_rr, KNOT_PF_FREE);
}

int kr_answer_opt_rr_add_cookies(const struct kr_srvr_cookie_input *input,
                                 const struct kr_srvr_cookie_alg_descr *alg,
                                 knot_pkt_t *pkt)
{
	if (!input || !alg || pkt) {
		kr_error(EINVAL);
	}

	uint16_t cookie_size = input->clnt_cookie_len + alg->srvr_cookie_size;
	uint8_t *data = NULL;

	if (!pkt->opt_rr) {
		kr_error(EINVAL);
	}
	int ret = knot_edns_reserve_option(pkt->opt_rr,
	                                   KNOT_EDNS_OPTION_COOKIE,
	                                   cookie_size, &data, &pkt->mm);
	if (ret != KNOT_EOK) {
		return kr_error(ret);
	}

	memcpy(data, input->clnt_cookie, input->clnt_cookie_len);
	cookie_size = alg->srvr_cookie_size;
	ret = alg->gen_func(input, data + input->clnt_cookie_len, &cookie_size);
	if (ret != kr_ok()) {
		/* TODO -- Delete COOKIE option. */
		return ret;
	}

	return ret;
}

int kr_pkt_set_ext_rcode(knot_pkt_t *pkt, uint16_t whole_rcode)
{
	if (!pkt || !knot_pkt_has_edns(pkt)) {
		return kr_error(EINVAL);
	}

	uint8_t rcode = whole_rcode & 0x0f;
	uint8_t ext_rcode = whole_rcode >> 4;
	knot_wire_set_rcode(pkt->wire, rcode);
	knot_edns_set_ext_rcode(pkt->opt_rr, ext_rcode);

	return kr_ok();
}

uint8_t *kr_is_cookie_query(const knot_pkt_t *pkt)
{
	if (!pkt || knot_wire_get_qdcount(pkt->wire) > 0) {
		return false;
	}

	if (knot_wire_get_qr(pkt->wire) != 0 || !pkt->opt_rr) {
		return false;
	}

	return knot_edns_get_option(pkt->opt_rr, KNOT_EDNS_OPTION_COOKIE);
}

int kr_parse_cookie_opt(uint8_t *cookie_opt, struct kr_dns_cookies *cookies)
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
