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

#include "lib/module.h"

/* Fake libgo */

void runtime_check(void) {}
void runtime_args(int argc, void *argv) {}
void runtime_osinit(void) {}
void runtime_schedinit(void) {}
void __go_init_main() {}

/*
 * No module implementation.
 */

/* @note Renamed to mimick Go module. */
#if defined(__APPLE__)
    extern uint32_t Api(void) __asm__ ("_main.Api"); /* Mach-O */
#elif _WIN32
    #error DLL format is not supported for Golang modules.
#else
    extern uint32_t Api(void) __asm__ ("main.Api");  /* ELF */
#endif


uint32_t Api(void)
{
    return KR_MODULE_API - 1; /* Bad version */
}