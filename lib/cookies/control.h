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
#include <stdbool.h>

#include "lib/defines.h"

#define KR_COOKIE_PLD_MAX 44 /* Define in libknot. */

/** Holds secret quantity. */
struct secret_quantity {
	size_t size; /*!< Secret quantity size. */
	const uint8_t *secret;
};

/** DNSSEC cookies controlling structure. */
struct cookies_control {
	bool enabled; /*!< Enabled/disables DNS cookies functionality. */
	struct secret_quantity *client; /*!< Client secret quantity. */
	/* TODO -- Cache. */
};

/** Global cookies control. */
KR_EXPORT
extern struct cookies_control kr_cookies_control;

/**
 * Insert a DNS cookie into query packet.
 * @note The packet must already contain ENDS section.
 * @param cntrl         Cookie control structure.
 * @param clnt_sockaddr Client address.
 * @param srvr_sockaddr Server address.
 * @param pkt           DNS request packet.
 */
KR_EXPORT
int kr_request_put_cookie(struct cookies_control *cntrl, void *clnt_sockaddr,
                          void *srvr_sockaddr, knot_pkt_t *pkt);
