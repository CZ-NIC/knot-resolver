/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once
#include "lib/defines.h"

// All functions here return combination of the following flags or kr_error(...).
enum mmapped_state {
	MMAPPED_PENDING              = 1,  // write lock acquired, (re)initialize and call finish
	MMAPPED_EXISTING             = 2,  // using existing data, check consistency
};

struct mmapped {
	void *mem;
	size_t size;
	int fd;
	bool write_lock;
	bool persistent;
};

/* Initialize/Use file data as mmapped memory.
 *
 * If write flock can be acquired and persistency is not requested, the file is resized, zeroed and mmapped,
 * header is copied at its beginning and MMAPPED_PENDING is returned;
 * you should finish initialization and call mmapped_init_finish to degrade flock to shared.
 *
 * Otherwise, it either acquires write flock or waits for shared flock,
 * calls mmap, verifies that header is byte-wise identical
 * and returns MMAPPED_EXISTING, possibly ORed with MMAPPED_PENDING based on the lock type.
 *
 * On header or size mismatch, either the outcome is the same as in the first case (if write flock was acquired),
 * or kr_error(ENOTRECOVERABLE) is returned;
 * on a system error, kr_error(errno) is returned.
 *
 * If size is set to zero, only using existing data is allowed. */
KR_EXPORT
int mmapped_init(struct mmapped *mmapped, const char *mmap_file, size_t size, void *header, size_t header_size, bool persistent);

/* Reinitialize mmapped data (incl. size) as in the first case of mmapped_init.
 *
 * To be called if existing mmapped file data cannot be used and we still own write flock
 * (i.e. MMAPPED_PENDING flag was returned from the last mmapped_ call).
 * Possible return values are the same as in mmapped_init.
 *
 * If MMAPPED_PENDING was not set, kr_error(ENOTRECOVERABLE) is returned. */
int mmapped_init_reset(struct mmapped *mmapped, const char *mmap_file, size_t size, void *header, size_t header_size);

/* Degrade flock to shared after getting MMAPPED_PENDING; void if MMAPPED_PENDING wasn't set.
 *
 * Returns zero on success and kr_error(errno) on system error. */
KR_EXPORT
int mmapped_init_finish(struct mmapped *mmapped);

/* Free mmapped memory and,
 * unless the underlying file is used by other processes or persistence is requested, truncate it to zero size. */
KR_EXPORT
void mmapped_deinit(struct mmapped *mmapped);


/* Detailed description of init return states:
	mmapped_init:
		PENDING:  (size > 0 only)
			new memory initialized, header copied there; first process with exclusive lock
			finish initialization and call _init_finish
		EXISTING | PENDING:  (persistent case only)
			using existing data with equal header; first process with exclusive lock
			possibly perform other checks / modifications and call _init_finish
				or call _init_reset
		EXISTING:
			using existing data with equal header; shared lock
			success; no further action required (but _init_finish possible)
		kr_error(ENOTRECOVERABLE):
			file header is not valid and
				exclusive lock cannot be acquired or
				reset is not allowed (size == 0)
		system error (<0)
	mmapped_init_reset:
		PENDING:
			new memory initialized, header copied; still exclusive lock
		kr_error(ENOTRECOVERABLE):
			exclusive lock not acquired or
			reset is not allowed (size == 0)
		system error (<0)
	mmapped_init_finish:
		0:
			lock degraded to shared (or was already)
			success; no further action required
		system error (<0)
*/


/* Example usage, based on state flags returned by above functions:

	persistent case:
		mmapped_init
		if (>=0 && EXISTING) {
			if (!valid) {
				mmapped_init_reset   // -> continue with init/fail below
			} else {
				mmapped_init_finish  // required only if PENDING
			}
		}
		if (>=0 && !EXISTING && PENDING) {  //  == PENDING
			... // init
			mmapped_init_finish
		}
		if (<0) fail + return
		assertion (==0) // if both _finish above were used
		// done

	non-persistent case:
		mmapped_init
		if (>=0 && EXISTING) {              //  == EXISTING
			if (!valid) fail + return
			mmapped_init_finish  // not required
		} else if (>=0 && PENDING) {        //  == PENDING
			... // init
			mmapped_init_finish
		}
		if (<0) fail + return
		assertion (==0) // no other outcome if both _finish above were used
		// done
*/

