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

/** \addtogroup utils
 * @{ 
 */

#pragma once

#include <stdio.h>

/*
 * General-purpose attributes.
 */
#define auto_free __attribute__((cleanup(_cleanup_free)))
extern void _cleanup_free(char **p);
#define auto_close __attribute__((cleanup(_cleanup_close)))
extern void _cleanup_close(int *p);
#define auto_fclose __attribute__((cleanup(_cleanup_fclose)))
extern void _cleanup_fclose(FILE **p);

/*
 * Defines.
 */

/** Concatenate N strings. */
char* kr_strcatdup(unsigned n, ...);

/** @} */
