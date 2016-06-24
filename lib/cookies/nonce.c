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

#include <arpa/inet.h>
#include <assert.h>

#include "lib/cookies/nonce.h"

int kr_nonce_write_wire(uint8_t *buf, uint16_t *buf_len,
                        struct kr_nonce_input *input)
{
	if (!buf || !buf_len || !input) {;
		return kr_error(EINVAL);
	}

	if (*buf_len < NONCE_LEN) {
		kr_error(EINVAL);
	}

	uint32_t aux = htonl(input->rand);
	memcpy(buf, &aux, sizeof(aux));
	aux = htonl(input->time);
	memcpy(buf + sizeof(aux), &aux, sizeof(aux));
	*buf_len = 2 * sizeof(aux);
	assert(NONCE_LEN == *buf_len);

	return kr_ok();
}
