/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "lib/defines.h"

/* RFC7873 Appendix B.2 mentions an algorithm using two values before the
 * actual server cookie hash. */

/** Nonce value length. */
#define KR_NONCE_LEN 8

/** Input data to generate nonce from. */
struct kr_nonce_input {
	uint32_t rand; /**< some random value */
	uint32_t time; /**< time stamp */
};

/**
 * @brief Writes server cookie nonce value into given buffer.
 *
 * @param buf     buffer to write nonce data in wire format into
 * @param buf_len buffer size
 * @param input   data to generate wire data from
 * @return non-zero size of written data on success, 0 on failure
 */
KR_EXPORT
uint16_t kr_nonce_write_wire(uint8_t *buf, uint16_t buf_len,
                             const struct kr_nonce_input *input);
