/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#include "lib/mmapped.h"
#include "lib/utils.h"

static inline bool fcntl_flock_whole(int fd, short int type, bool wait)
{
	struct flock fl = {
		.l_type   = type,      // F_WRLCK, F_RDLCK, F_UNLCK
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0 };
	return fcntl(fd, (wait ? F_SETLKW : F_SETLK), &fl) != -1;
}

int mmapped_init(struct mmapped *mmapped, const char *mmap_file, size_t size, void *header, size_t header_size)
{
	int ret = 0;
	int fd = mmapped->fd = open(mmap_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		ret = kr_error(errno);
		kr_log_crit(SYSTEM, "Cannot open file %s with shared data: %s\n",
				mmap_file, strerror(errno));
		goto fail;
	}

	// try to acquire write lock; copy header on success
	if (fcntl_flock_whole(fd, F_WRLCK, false)) {
		if (ftruncate(fd, 0) == -1 || ftruncate(fd, size) == -1) {  // get all zeroed
			ret = kr_error(errno);
			kr_log_crit(SYSTEM, "Cannot change size of file %s containing shared data: %s\n",
					mmap_file, strerror(errno));
			goto fail;
		}
		mmapped->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (mmapped->mem == MAP_FAILED) goto fail_errno;

		memcpy(mmapped->mem, header, header_size);

		return MMAPPED_WAS_FIRST;
	}

	// wait for acquiring shared lock; check header on success
	if (!fcntl_flock_whole(fd, F_RDLCK, true)) goto fail_errno;

	struct stat s;
	bool succ = (fstat(fd, &s) == 0);
	if (!succ) goto fail_errno;
	if (s.st_size != size) goto fail_header_mismatch;

	mmapped->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mmapped->mem == MAP_FAILED) goto fail_errno;
	if (memcmp(mmapped->mem, header, header_size) != 0) {
		munmap(mmapped->mem, size);
		goto fail_header_mismatch;
	}

	return 0;


fail_header_mismatch:
	kr_log_crit(SYSTEM, "Another instance of kresd uses file %s with different configuration.", mmap_file);
	errno = ENOTRECOVERABLE;

fail_errno:
	ret = kr_error(errno);

fail:
	if (fd >= 0) {
		fcntl_flock_whole(fd, F_UNLCK, false);
		close(fd);
	}
	mmapped->mem = NULL;
	return ret;
}

int mmapped_init_continue(struct mmapped *mmapped)
{
	if (!fcntl_flock_whole(mmapped->fd, F_RDLCK, false)) return kr_error(errno);
	return 0;
}

void mmapped_deinit(struct mmapped *mmapped)
{
	if (mmapped->mem == NULL) return;
	int fd = mmapped->fd;

	munmap(mmapped->mem, mmapped->size);
	mmapped->mem = NULL;

	fcntl_flock_whole(fd, F_UNLCK, false);

	// remove file data unless it is still locked by other processes
	if (fcntl_flock_whole(fd, F_WRLCK, false)) {

		/* If the configuration is updated at runtime, manager may remove the file
		 * and the new processes create it again while old processes are still using the old data.
		 * Here we keep zero-size file not to accidentally remove the new file instead of the old one.
		 * Still truncating the file will cause currently starting processes waiting for read lock on the same file to fail,
		 * but such processes are not expected to exist. */
		ftruncate(fd, 0);

		fcntl_flock_whole(fd, F_UNLCK, false);
	}
	close(fd);
}
