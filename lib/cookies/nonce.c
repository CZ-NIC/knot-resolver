/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libknot/wire.h>
#include "lib/cookies/nonce.h"

uint16_t kr_nonce_write_wire(uint8_t *buf, uint16_t buf_len,
                             const struct kr_nonce_input *input)
{
	if (!buf || buf_len < KR_NONCE_LEN || !input) {
		return 0;
	}

	knot_wire_write_u32(buf, input->rand);
	knot_wire_write_u32(buf + sizeof(uint32_t), input->time);
	buf_len = 2 * sizeof(uint32_t);

	return buf_len;
}
