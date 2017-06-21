/*  Copyright (C) 2016-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//TODO: cleanup, etc.
#include <arpa/inet.h>
#include <lib/defines.h>
#include <assert.h>
#include <errno.h>
#include <histedit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

FILE *g_tty = NULL;		//!< connection to the daemon

//! Initialize connection to the daemon; return 0 on success.
KR_EXPORT int kr_init_tty(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 1;

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	size_t plen = strlen(path);
	if (plen + 1 > sizeof(addr.sun_path)) {
		fprintf(stderr, "Path too long\n");
		close(fd);
		return 1;
	}
	memcpy(addr.sun_path, path, plen + 1);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr))) {
		perror("While connecting to daemon");
		close(fd);
		return 1;
	}
	g_tty = fdopen(fd, "r+");
	if (!g_tty) {
		perror("While opening TTY");
		close(fd);
		return 1;
	}

	// Switch to binary mode and consume the text "> ".
	if (fprintf(g_tty, "__binary\n") < 0 || !fread(&addr, 2, 1, g_tty)
	    || fflush(g_tty)) {
		perror("While initializing TTY");
		fclose(g_tty);
		g_tty = NULL;
		return 1;
	}

	return 0;
}

//! Run a command on the daemon; return the answer or NULL on failure, puts answer length to out_len.
KR_EXPORT char *kr_run_cmd(const char *cmd, size_t * out_len)
{
	if (!g_tty || !cmd) {
		assert(false);
		return NULL;
	}
	if (fprintf(g_tty, "%s", cmd) < 0 || fflush(g_tty))
		return NULL;
	uint32_t len;
	if (!fread(&len, sizeof(len), 1, g_tty))
		return NULL;
	len = ntohl(len);
	char *msg = malloc(1 + (size_t) len);
	if (!msg)
		return NULL;
	if (len && !fread(msg, len, 1, g_tty)) {
		free(msg);
		return NULL;
	}
	msg[len] = '\0';
	*out_len = len;
	return msg;
}

