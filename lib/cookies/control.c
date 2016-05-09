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
#include <stdint.h>
#include <libknot/error.h>
#include <libknot/rrtype/opt_cookie.h>

#include "lib/cookies/control.h"

struct cookies_control cookies_control = {
	.enabled = true
};

static int opt_rr_add_cookies(knot_rrset_t *opt_rr,
                              uint8_t cc[KNOT_OPT_COOKIE_CLNT],
                              uint8_t *sc, uint16_t sc_len,
                              knot_mm_t *mm)
{
	int ret;
	uint16_t cookies_size = 0;
	uint8_t *cookies_data = NULL;

	cookies_size = knot_edns_opt_cookie_data_len(sc_len);

	ret = knot_edns_reserve_option(opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                               cookies_size, &cookies_data, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(cookies_data != NULL);

	ret = knot_edns_opt_cookie_create(cc, sc, sc_len,
	                                  cookies_data, &cookies_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(cookies_size == knot_edns_opt_cookie_data_len(sc_len));

	return KNOT_EOK;
}

int kr_pkt_add_cookie(knot_pkt_t *pkt)
{
	assert(pkt);
	assert(pkt->opt_rr);

	/* TODO -- generate cleitn cookie from client address, server address
	 * and secret quentity. */
	static uint8_t cc[KNOT_OPT_COOKIE_CLNT] = { 1, 2, 3, 4, 5, 6, 7, 8};

	int ret = opt_rr_add_cookies(pkt->opt_rr, cc, NULL, 0, &pkt->mm);
	return ret;
}
