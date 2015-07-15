/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/**
 * Initialise cryptographic back-end.
 */
void kr_crypto_init(void);

/**
 * De-initialise cryptographic back-end.
 */
void kr_crypto_cleanup(void);

/**
 * Re-initialise cryptographic back-end.
 * @note Must be called after fork() in the child.
 */
void kr_crypto_reinit(void);

/**
 * Check whether the DNSKEY rrset matches the supplied trust anchor RRSet.
 * @param sec Packet section containing the DNSKEY RRSet including its signatures.
 * @param key DNSKEY RRSet to check.
 * @param ta  Trust anchor RRSet agains which to validate the DNSKEY.
 * @return     0 or error code.
 */
int kr_dnskey_trusted(const knot_pktsection_t *sec, const knot_rrset_t *keys, const knot_rrset_t *ta);
