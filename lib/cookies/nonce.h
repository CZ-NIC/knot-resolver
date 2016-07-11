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

#include "lib/defines.h"

/* RFC7873 Appendix B.2 mentions an algorithm using two values before the
 * actual server cookie hash. */

/** Nonce value length. */
#define NONCE_LEN 8

/** Input data to generate nonce from. */
struct kr_nonce_input {
	uint32_t rand; /**< some random value */
	uint32_t time; /**< time stamp */
};

/**
 * @brief Writes server cookie nonce value into given buffer.
 *
 * @param buf     buffer to write nonce data in wire format into
 * @param buf_len on input contains nonce buffer size, on output contains
 *                size of actual written data
 * @param input   data to generate wire data from
 * @return kr_ok() on success, error code else
 */
KR_EXPORT
int kr_nonce_write_wire(uint8_t *buf, uint16_t *buf_len,
                        struct kr_nonce_input *input);
