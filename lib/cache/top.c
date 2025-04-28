/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <limits.h>
#include "lib/defines.h"
#include "lib/cache/top.h"

// #ifdef LOG_GRP_MDB
#define VERBOSE_LOG(...) printf("GC KRU " __VA_ARGS__)

struct kr_cache_top {
	bool using_avx2;  // required consistency to use the same hash function
	// --- header end ---
	size_t capacity;
	uint32_t instant_limit;  // warn about different settings, but require explicit file removal?
	uint32_t rate_limit;
	uint32_t time_offset;    // to be set on reinit according to last_change timestamp
	_Atomic uint32_t last_change;
	_Alignas(64) uint8_t kru[];
};

bool kr_cache_top_init(void) {

	return true;
}

void kr_cache_top_deinit(void) {

}

/* text mode: '\0' -> '|'
 * hex bytes: <x00010203x>
 * decimal bytes: <0.1.2.3>
 */
static char *str_key(void *key, size_t len) {
	static char str[401];
	if (4 * len + 1 > sizeof(str)) len = (sizeof(str) - 1) / 4;
	unsigned char *k = key;

	bool bytes_mode = false;
	bool decimal_bytes = false;
	int force_bytes = 0;
	char *strp = str;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = k[i];
		if ((force_bytes-- <= 0) &&
				((c == 0) || ((c > ' ') && (c <= '~') && (c != '|') && (c != '<') && (c != '>')))) {
			//if (c == ' ') c = '_';
			if (c == 0)   c = '|';
			if (bytes_mode) {
				if (decimal_bytes) strp--;
				*strp++ = '>';
				bytes_mode = false;
				decimal_bytes = false;
			}
			*strp++ = c;
			if ((i > 0) && (k[i - 1] == '\0') && ((i == 1) || k[i - 2] == '\0')) {
				switch (k[i]) {
					case 'S':
						if (len == 6) decimal_bytes = true;
						// pass through
					case '3':
						force_bytes = INT_MAX;
						break;
					case 'E':
						force_bytes = true;
						decimal_bytes = true;
						break;
				}
			}
		} else {
			if (!bytes_mode) {
				*strp++ = '<';
				if (!decimal_bytes) *strp++ = 'x';
				bytes_mode = true;
			}
			if (decimal_bytes) {
				if (c >= 100) *strp++ = '0' + c / 100;
				if (c >= 10)  *strp++ = '0' + c / 10 % 10;
				*strp++ = '0' + c % 10;
				*strp++ = '.';
			} else {
				*strp++ = "0123456789ABCDEF"[c >> 4];
				*strp++ = "0123456789ABCDEF"[c & 15];
			}
		}
	}
	if (bytes_mode) {
		if (decimal_bytes) {
			strp--;
		} else {
			*strp++ = 'x';
		}
		*strp++ = '>';
		bytes_mode = false;
	}
	*strp++ = '\0';
	return str;
}

void kr_cache_top_access(struct kr_cache_top *top, void *key, size_t len, char *debug_label) {

	VERBOSE_LOG("ACCESS %-19s %s\n", debug_label, str_key(key, len));
}

// temporal logging one level under _access
void kr_cache_top_access_cdb(struct kr_cache_top *top, void *key, size_t len, char *debug_label) {

	VERBOSE_LOG("ACCESS   %-17s %s\n", debug_label, str_key(key, len));
}

uint16_t kr_cache_top_load(void *key, size_t len) {
	uint16_t load = 0;

	VERBOSE_LOG("LOAD %s -> %d\n", str_key(key, len), load);
	return load;
}
