/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lib/defines.h"

#define MMAPPED_WAS_FIRST 1

struct mmapped {
	void *mem;
	size_t size;
	int fd;
};

/* Initialize/Use file data as mmapped memory.
 *
 * If write flock can be acquired, the file is resized, zeroed and mmapped,
 * header is copied at its beginning and MMAPPED_WAS_FIRST is returned;
 * you should finish initialization and call mmapped_init_continue to degrade flock to shared.
 * Otherwise, it waits for shared flock, calls mmap, verifies that header is byte-wise identical and returns zero.
 * On header mismatch, kr_error(ENOTRECOVERABLE) is returned; on a system error, kr_error(errno) is returned. */
KR_EXPORT
int mmapped_init(struct mmapped *mmapped, const char *mmap_file, size_t size, void *header, size_t header_size);

/* Degrade flock to shared after getting MMAPPED_WAS_FIRST from mmapped_init.
 *
 * Returns zero on success and kr_error(errno) on system error. */
KR_EXPORT
int mmapped_init_continue(struct mmapped *mmapped);

/* Free mmapped memory and, unless the underlying file is used by other processes, truncate it to zero size. */
KR_EXPORT
void mmapped_deinit(struct mmapped *mmapped);
