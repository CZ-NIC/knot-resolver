/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <cmocka.h>

/* Silence clang/GCC warnings when using cmocka 1.0 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "lib/defines.h"
#include "lib/utils.h"
#include <libknot/descriptor.h>
#include <libknot/rrset.h>

/* Helpers */
static inline void *mm_test_malloc(void *ctx, size_t n)
{ return test_malloc(n); }
static inline void mm_test_free(void *p)
{ if (p) test_free(p); }

/** Memory context using CMocka allocator. */
static inline void test_mm_ctx_init(knot_mm_t *mm)
{
	mm->alloc = &mm_test_malloc;
	mm->free = &mm_test_free;
}

/** Recursively delete directory. */
static inline int test_tmpdir_remove(const char *path)
{
	char buf[512];
	struct dirent *ent = NULL;
	DIR *dir = opendir(path);
	if (dir == NULL) {
		return kr_error(errno);
	}
	while ((ent = readdir(dir)) != NULL) {
		/* Skip special dirs (this presumes no files begin with '.') */
		if (ent->d_name[0] == '.') {
			continue;
		}
		sprintf(buf, "%s/%s", path, ent->d_name);
		remove(buf);
	}
	remove(path);
	closedir(dir);
	return 0;
}

/** Create temporary directory. */
static inline const char* test_tmpdir_create(void)
{
	static char env_path[64];
	strcpy(env_path, "./tmpXXXXXX");
	return mkdtemp(env_path);
}

/** Generate random string with given length. */
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

/** Init RRSet with type TXT, random owner and random payload.
 *  @note Static memory reused, copy it if you need persistence.
 */
static inline void test_random_rr(knot_rrset_t *rr, uint32_t ttl)
{
	static uint8_t owner_buf[KNOT_DNAME_MAXLEN] = { 0 };
	static uint8_t rdata_buf[65535];
	knot_rdata_t *rdata = (knot_rdata_t *)rdata_buf;

	uint16_t num = rand() % (sizeof(owner_buf) - 2);
	uint8_t tmp_buf[KNOT_DNAME_MAXLEN];

	/* Create random label. */
	uint8_t label_len = num % KNOT_DNAME_MAXLABELLEN;
	owner_buf[0] = label_len;
	test_randstr((char *)(owner_buf + 1), label_len);

	/* Create payload */
	tmp_buf[0] = num;
	test_randstr((char *)(tmp_buf + 1), tmp_buf[0] + 1);
	knot_rdata_init(rdata, num + 1, tmp_buf);

	/* Assign static buffers. */
	knot_rrset_init(rr, owner_buf, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, ttl);
	rr->rrs.count = 1;
	rr->rrs.rdata = rdata;
}

