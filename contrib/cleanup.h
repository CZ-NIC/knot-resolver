/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/**
 * Cleanup attributes.
 * @cond internal
 */
#pragma once
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define auto_free __attribute__((cleanup(_cleanup_free)))
static inline void _cleanup_free(char **p) {
	free(*p);
}
#define auto_close __attribute__((cleanup(_cleanup_close)))
static inline void _cleanup_close(int *p) {
	if (*p > 0) close(*p);
}
#define auto_fclose __attribute__((cleanup(_cleanup_fclose)))
static inline void _cleanup_fclose(FILE **p) {
	if (*p) fclose(*p);
}
/* @endcond */