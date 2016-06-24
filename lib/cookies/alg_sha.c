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

#include <arpa/inet.h> /* htonl(), ... */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <libknot/errcode.h>
#include <libknot/rrtype/opt-cookie.h>

#include "lib/cookies/alg_sha.h"
#include "lib/utils.h"

/**
 * Compute client cookie using HMAC_SHA256-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @param cc_len Size of buffer/written data.
 * @return KNOT_EOK on success, error code else.
 */
static int cc_gen_hmac_sha256_64(const struct knot_cc_input *input,
                                 uint8_t *cc_out, uint16_t *cc_len)
{
	if (!input || !cc_out || !cc_len) {
		return KNOT_EINVAL;
	}

	if ((!input->clnt_sockaddr && !input->srvr_sockaddr) ||
	    !(input->secret_data && input->secret_len)) {
		return KNOT_EINVAL;
	}

	const uint8_t *addr = NULL;
	int addr_len = 0; /* Address length. */

	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = SHA256_DIGEST_LENGTH;

	/* text: (client IP | server IP)
	 * key: client secret */

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	int ret = HMAC_Init_ex(&ctx, input->secret_data, input->secret_len,
	                       EVP_sha256(), NULL);
	if (ret != 1) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	if (input->clnt_sockaddr) {
		addr = (uint8_t *)kr_inaddr(input->clnt_sockaddr);
		addr_len = kr_inaddr_len(input->clnt_sockaddr);
		if (addr && addr_len > 0) {
			ret = HMAC_Update(&ctx, addr, addr_len);
			if (ret != 1) {
				ret = KNOT_EINVAL;
				goto fail;
			}
		}
	}

	if (input->srvr_sockaddr) {
		addr = (uint8_t *)kr_inaddr(input->srvr_sockaddr);
		addr_len = kr_inaddr_len(input->srvr_sockaddr);
		if (addr && addr_len > 0) {
			ret = HMAC_Update(&ctx, addr, addr_len);
			if (ret != 1) {
				ret = KNOT_EINVAL;
				goto fail;
			}
		}
	}

	if (1 != HMAC_Final(&ctx, digest, &digest_len)) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	assert(KNOT_OPT_COOKIE_CLNT <= SHA256_DIGEST_LENGTH);
	if (*cc_len < KNOT_OPT_COOKIE_CLNT) {
		return KNOT_ESPACE;
	}

	*cc_len = KNOT_OPT_COOKIE_CLNT;
	memcpy(cc_out, digest, *cc_len);
	ret = KNOT_EOK;

fail:
	HMAC_CTX_cleanup(&ctx);
	return ret;
}

#define SRVR_HMAC_SHA256_64_HASH_SIZE 8

/**
 * @brief Compute server cookie using HMAC-SHA256-64).
 * @note Server cookie = nonce | time | HMAC-SHA256-64( server secret, client cookie | nonce| time | client IP )
 * @param input    data to compute cookie from
 * @param hash_out hash cookie output buffer
 * @param hash_len buffer size / written data size
 * @return KNOT_EOK or error code.
 */
static int sc_gen_hmac_sha256_64(const struct knot_sc_input *input,
                                 uint8_t *hash_out, uint16_t *hash_len)
{
	if (!input || !hash_out ||
	    !hash_len || (*hash_len < SRVR_HMAC_SHA256_64_HASH_SIZE)) {
		return KNOT_EINVAL;
	}

	if (!input->cc || !input->cc_len || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return KNOT_EINVAL;
	}

	const uint8_t *addr = NULL;
	size_t addr_len = 0; /* Address length. */

	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned int digest_len = SHA256_DIGEST_LENGTH;

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	int ret = HMAC_Init_ex(&ctx, input->srvr_data->secret_data,
	                       input->srvr_data->secret_len,
	                       EVP_sha256(), NULL);
	if (ret != 1) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	ret = HMAC_Update(&ctx, input->cc, input->cc_len);
	if (ret != 1) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	if (input->nonce && input->nonce_len) {
		ret = HMAC_Update(&ctx, (void *)input->nonce, input->nonce_len);
		if (ret != 1) {
			ret = KNOT_EINVAL;
			goto fail;
		}
	}

	if (input->srvr_data->clnt_sockaddr) {
		addr = (uint8_t *)kr_inaddr(input->srvr_data->clnt_sockaddr);
		addr_len = kr_inaddr_len(input->srvr_data->clnt_sockaddr);
		if (addr && addr_len > 0) {
			ret = HMAC_Update(&ctx, addr, addr_len);
			if (ret != 1) {
				ret = KNOT_EINVAL;
				goto fail;
			}
		}
	}

	if (1 != HMAC_Final(&ctx, digest, &digest_len)) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	assert(SRVR_HMAC_SHA256_64_HASH_SIZE <= SHA256_DIGEST_LENGTH);

	*hash_len = SRVR_HMAC_SHA256_64_HASH_SIZE;
	memcpy(hash_out, digest, *hash_len);

	ret = KNOT_EOK;

fail:
	HMAC_CTX_cleanup(&ctx);
	return ret;
}

const struct knot_cc_alg knot_cc_alg_hmac_sha256_64 = { KNOT_OPT_COOKIE_CLNT, cc_gen_hmac_sha256_64 };

const struct knot_sc_alg knot_sc_alg_hmac_sha256_64 = { SRVR_HMAC_SHA256_64_HASH_SIZE, sc_gen_hmac_sha256_64 };
