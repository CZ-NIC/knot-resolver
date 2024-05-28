/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

// Checked with clang 5 (2017) and gcc 6 (2016).
// For other cases we'll rather keep just the generic implementation.
#if defined(__x86_64__) && (__clang_major__ >= 5 || __GNUC__ >= 6)

// This file has code for new-ish x86 (2015+ usually, Atom 2021+) - AES + AVX2
#if __clang_major__ >= 12
	#pragma clang attribute push (__attribute__((target("arch=x86-64-v3,aes"))), \
							apply_to = function)
#elif __clang__
	#pragma clang attribute push (__attribute__((target("avx2,aes"))), \
							apply_to = function)
#else
	#pragma GCC push_options
	#if __GNUC__ >= 11
		#pragma GCC target("arch=x86-64-v3,aes")
		// try harder for auto-vectorization, etc.
		#pragma GCC optimize("O3")
	#else
		#pragma GCC target("avx2,aes")
	#endif
#endif

#define USE_AES 1
#define USE_AVX2 1
#define USE_SSE41 1

#include "./kru.inc.c"
const struct kru_api KRU_AVX2 = KRU_API_INITIALIZER;

#ifdef __clang__
	#pragma clang attribute pop
#else
	#pragma GCC pop_options
#endif

__attribute__((constructor))
static void detect_CPU_avx2(void)
{
	// Checking just AES+AVX2 will most likely be OK even if we used arch=x86-64-v3
	if (__builtin_cpu_supports("aes") && __builtin_cpu_supports("avx2")) {
		KRU = KRU_AVX2;
	}
}

#else

#include "./kru.h"
const struct kru_api KRU_AVX2 = {NULL};

#endif
