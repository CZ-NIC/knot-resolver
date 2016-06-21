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
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <libknot/errcode.h>
#include <libknot/rrtype/opt_cookie.h>

#include "contrib/fnv/fnv.h"
#include "lib/cookies/alg_clnt.h"

//#define CC_HASH_USE_CLIENT_ADDRESS /* When defined, client address will be used when generating client cookie. */

/**
 * Compute client cookie using FNV-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @param cc_len Size of buffre/written data.
 * @return KNOT_EOK on success, error code else.
 */
static int kr_clnt_cookie_alg_fnv64(const struct knot_ccookie_input *input,
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
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

#if defined(CC_HASH_USE_CLIENT_ADDRESS)
	if (input->clnt_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->clnt_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf(addr, alen, hash_val);
		}
	}
#endif /* defined(CC_HASH_USE_CLIENT_ADDRESS) */

	if (input->srvr_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->srvr_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
		}
	}

	hash_val = fnv_64a_buf((void *) input->secret_data, input->secret_len,
	                       hash_val);

	assert(KNOT_OPT_COOKIE_CLNT == sizeof(hash_val));
	if (*cc_len < KNOT_OPT_COOKIE_CLNT) {
		return KNOT_ESPACE;
	}

	*cc_len = KNOT_OPT_COOKIE_CLNT;
	memcpy(cc_out, &hash_val, *cc_len);

	return KNOT_EOK;
}

/**
 * Compute client cookie using HMAC_SHA256-64.
 * @note At least one of the arguments must be non-null.
 * @param input  Input parameters.
 * @param cc_out Buffer for computed client cookie.
 * @param cc_len Size of buffre/written data.
 * @return KNOT_EOK on success, error code else.
 */
static int kr_clnt_cookie_alg_hmac_sha256_64(const struct knot_ccookie_input *input,
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
	size_t alen = 0; /* Address length. */

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

#if defined(CC_HASH_USE_CLIENT_ADDRESS)
	if (input->clnt_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->clnt_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			ret = HMAC_Update(&ctx, addr, alen);
			if (ret != 1) {
				ret = KNOT_EINVAL;
				goto fail;
			}
		}
	}
#endif /* defined(CC_HASH_USE_CLIENT_ADDRESS) */

	if (input->srvr_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->srvr_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			ret = HMAC_Update(&ctx, addr, alen);
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

const struct kr_clnt_cookie_alg_descr kr_clnt_cookie_algs[] = {
	{ "FNV-64", { KNOT_OPT_COOKIE_CLNT, kr_clnt_cookie_alg_fnv64 } },
	{ "HMAC-SHA256-64", { KNOT_OPT_COOKIE_CLNT, kr_clnt_cookie_alg_hmac_sha256_64 } },
	{ NULL, { 0, NULL } }
};

const struct kr_clnt_cookie_alg_descr *kr_clnt_cookie_alg(const struct kr_clnt_cookie_alg_descr cc_algs[],
                                                          const char *name)
{
	if (!cc_algs || !name) {
		return NULL;
	}

	const struct kr_clnt_cookie_alg_descr *aux_ptr = cc_algs;
	while (aux_ptr && aux_ptr->alg.gen_func) {
		assert(aux_ptr->name);
		if (strcmp(aux_ptr->name, name) == 0) {
			return aux_ptr;
		}
		++aux_ptr;
	}

	return NULL;
}

int kr_clnt_cookie_check(const uint8_t *cc, uint16_t cc_len,
                         const struct knot_ccookie_input *input,
                         const struct kr_clnt_cookie_alg_descr *cc_alg)
{
	if (!cc || !cc_len || !input || !cc_alg) {
		return kr_error(EINVAL);
	}

	int ret = knot_ccookie_check(cc, cc_len, input, &cc_alg->alg);

	return (ret == KNOT_EOK) ? kr_ok() : kr_error(EINVAL);
}
