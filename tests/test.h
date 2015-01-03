/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef __linux__
#define _XOPEN_SOURCE 500
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <ftw.h>
#include <unistd.h>
#include <cmocka.h>

#include <libknot/internal/mempattern.h>
#include <libknot/descriptor.h>
#include <libknot/rrset.h>
#include <libknot/errcode.h>

/*! \brief Memory context using CMocka allocator. */
static inline void test_mm_ctx_init(mm_ctx_t *mm)
{
	mm_ctx_init(mm);
}

static inline int _remove_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	return remove(fpath);
}

/*! \brief Recursively delete directory. */
static inline int test_tmpdir_remove(const char *path)
{
	return nftw(path, _remove_file, 64, FTW_DEPTH | FTW_PHYS);
}

/*! \brief Create temporary directory. */
static inline const char* test_tmpdir_create(void)
{
	static char env_path[64] = "./tmpXXXXXX";
	return mkdtemp(env_path);
}

/*! \brief Generate random string with given length. */
static inline void test_randstr(char* dst, size_t len)
{
	if (len == 0) {
		return;
	}

	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';
	return;
}

/*! \brief Init RRSet with type TXT, random owner and random payload.
 *  \note Static memory reused, copy it if you need persistence.
 */
static inline void test_random_rr(knot_rrset_t *rr, uint32_t ttl)
{
	static uint8_t owner_buf[KNOT_DNAME_MAXLEN];
	static uint8_t rdata_buf[65535];

	uint16_t num = rand() % (sizeof(owner_buf) - 2);
	uint8_t tmp_buf[KNOT_DNAME_MAXLEN];

	/* Create random label. */
	owner_buf[0] = num;
	test_randstr((char *)(owner_buf + 1), owner_buf[0] + 1);

	/* Create payload */
	tmp_buf[0] = num;
	test_randstr((char *)(tmp_buf + 1), tmp_buf[0] + 1);
	knot_rdata_init(rdata_buf, num + 1, tmp_buf, ttl);

	/* Assign static buffers. */
	knot_rrset_init(rr, owner_buf, KNOT_RRTYPE_TXT, KNOT_CLASS_IN);
	rr->rrs.rr_count = 1;
	rr->rrs.data = rdata_buf;
}

