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

#define KR_COOKIE_PLD_MAX 44 /* Define in libknot. */

/** DNSSEC cookies controlling structure. */
struct cookies_control {
	bool enabled; /*!< Enabled/disables DNS cookies functionality. */
	/* Cache. */
};

/** Global cookies control. */
extern struct cookies_control cookies_control;

/**
 * Insert a DNS cookie into the packet.
 * @note The packet must already contain ENDS section.
 * @param pkt Packet.
 */
int kr_pkt_add_cookie(knot_pkt_t *pkt);
