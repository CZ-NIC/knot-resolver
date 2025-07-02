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

static inline int fail(struct mmapped *mmapped, int ret)
{
	if (!ret) ret = kr_error(errno);
	if (mmapped->mem) {
		munmap(mmapped->mem, mmapped->size);
		mmapped->mem = NULL;
	}
	if (mmapped->fd >= 0) {
		fcntl_flock_whole(mmapped->fd, F_UNLCK, false);
		close(mmapped->fd);
		mmapped->fd = -1;
	}
	return ret;
}

int mmapped_init_reset(struct mmapped *mmapped, const char *mmap_file, size_t size, void *header, size_t header_size)
{
	kr_require(mmapped->fd);

	if (!size) { // reset not allowed
		kr_log_crit(SYSTEM, "File %s does not contain data in required format.\n", mmap_file);
		errno = ENOTRECOVERABLE;
		return fail(mmapped, 0);
	}

	if (!mmapped->write_lock) {
		kr_log_crit(SYSTEM, "Another instance of kresd uses file %s with different configuration.\n", mmap_file);
		errno = ENOTRECOVERABLE;
		return fail(mmapped, 0);
	}

	if (mmapped->mem) {
		munmap(mmapped->mem, mmapped->size);
		mmapped->mem = NULL;
	}

	kr_assert(size >= header_size);

	if ((ftruncate(mmapped->fd, 0) == -1) || (ftruncate(mmapped->fd, size) == -1)) {  // get all zeroed
		int ret = kr_error(errno);
		kr_log_crit(SYSTEM, "Cannot change size of file %s containing shared data: %s\n",
				mmap_file, strerror(errno));
		return fail(mmapped, ret);
	}

	mmapped->size = size;
	mmapped->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, mmapped->fd, 0);
	if (mmapped->mem == MAP_FAILED) return fail(mmapped, 0);

	memcpy(mmapped->mem, header, header_size);
	return MMAPPED_PENDING;
}


int mmapped_init(struct mmapped *mmapped, const char *mmap_file, size_t size, void *header, size_t header_size, bool persistent)
{
	// open file
	int ret = 0;
	mmapped->fd = open(mmap_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (mmapped->fd == -1) {
		ret = kr_error(errno);
		kr_log_crit(SYSTEM, "Cannot open file %s with shared data: %s\n",
				mmap_file, strerror(errno));
		return fail(mmapped, ret);
	}
	mmapped->persistent = persistent;

	// try to acquire write lock; wait for shared lock otherwise
	if (fcntl_flock_whole(mmapped->fd, F_WRLCK, false)) {
		mmapped->write_lock = true;
	} else if (fcntl_flock_whole(mmapped->fd, F_RDLCK, true)) {
		mmapped->write_lock = false;
	} else {
		return fail(mmapped, 0);
	}

	// get file size
	{
		struct stat s;
		bool succ = (fstat(mmapped->fd, &s) == 0);
		if (!succ) return fail(mmapped, 0);
		mmapped->size = s.st_size;
	}

	// reinit if non-persistent or wrong size
	if ((!persistent && mmapped->write_lock) || (size && (mmapped->size != size)) || (mmapped->size < header_size)) {
		return mmapped_init_reset(mmapped, mmap_file, size, header, header_size);
	}

	// mmap
	mmapped->mem = mmap(NULL, mmapped->size, PROT_READ | PROT_WRITE, MAP_SHARED, mmapped->fd, 0);
	if (mmapped->mem == MAP_FAILED) return fail(mmapped, 0);

	// check header
	if (memcmp(mmapped->mem, header, header_size) != 0) {
		return mmapped_init_reset(mmapped, mmap_file, size, header, header_size);
	}

	return MMAPPED_EXISTING | (mmapped->write_lock ? MMAPPED_PENDING : 0);
}

int mmapped_init_finish(struct mmapped *mmapped)
{
	kr_require(mmapped->fd);
	if (!mmapped->write_lock) return 0;  // mmapped already finished
	if (!fcntl_flock_whole(mmapped->fd, F_RDLCK, false)) return kr_error(errno);
	mmapped->write_lock = false;
	return 0;
}

void mmapped_deinit(struct mmapped *mmapped)
{
	if (mmapped->mem == NULL) return;

	munmap(mmapped->mem, mmapped->size);
	mmapped->mem = NULL;

	fcntl_flock_whole(mmapped->fd, F_UNLCK, false);

	// remove file data if non-persistent unless it is still locked by other processes
	if (!mmapped->persistent && fcntl_flock_whole(mmapped->fd, F_WRLCK, false)) {

		/* If the configuration is updated at runtime, manager may remove the file
		 * and the new processes create it again while old processes are still using the old data.
		 * Here we keep zero-size file not to accidentally remove the new file instead of the old one.
		 * Still truncating the file will cause currently starting processes waiting for read lock on the same file to fail,
		 * but such processes are not expected to exist. */
		ftruncate(mmapped->fd, 0);

		fcntl_flock_whole(mmapped->fd, F_UNLCK, false);
	}
	close(mmapped->fd);
}
