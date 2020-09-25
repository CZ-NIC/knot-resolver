/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libknot/rrtype/opt.h>
#include <string.h>

#include "lib/cookies/lru_cache.h"
#include "lib/utils.h"

const uint8_t *kr_cookie_lru_get(kr_cookie_lru_t *cache,
                                 const struct sockaddr *sa)
{
	if (!cache || !sa) {
		return NULL;
	}

	int addr_len = kr_inaddr_len(sa);
	const char *addr = kr_inaddr(sa);
	if (!addr || addr_len <= 0) {
		return NULL;
	}

	struct cookie_opt_data *cached = lru_get_try(cache, addr, addr_len);
	return cached ? cached->opt_data : NULL;
}

int kr_cookie_lru_set(kr_cookie_lru_t *cache, const struct sockaddr *sa,
                      uint8_t *opt)
{
	if (!cache || !sa) {
		return kr_error(EINVAL);
	}

	if (!opt) {
		return kr_ok();
	}

	int addr_len = kr_inaddr_len(sa);
	const char *addr = kr_inaddr(sa);
	if (!addr || addr_len <= 0) {
		return kr_error(EINVAL);
	}

	uint16_t opt_size = KNOT_EDNS_OPTION_HDRLEN +
	                    knot_edns_opt_get_length(opt);

	if (opt_size > KR_COOKIE_OPT_MAX_LEN) {
		return kr_error(EINVAL);
	}

	struct cookie_opt_data *cached = lru_get_new(cache, addr, addr_len, NULL);
	if (cached) {
		memcpy(cached->opt_data, opt, opt_size);
	}

	return kr_ok();
}
