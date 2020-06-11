/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_EXPLICIT_BZERO)
  #if defined(HAVE_BSD_STRING_H)
    #include <bsd/string.h>
  #endif
  /* #include <string.h> is needed. */
#elif defined(HAVE_EXPLICIT_MEMSET)
  /* #include <string.h> is needed. */
#elif defined(HAVE_GNUTLS_MEMSET)
  #include <gnutls/gnutls.h>
#else
  #define USE_CUSTOM_MEMSET
#endif

#include "string.h"
#include "ctype.h"

uint8_t *memdup(const uint8_t *data, size_t data_size)
{
	uint8_t *result = (uint8_t *)malloc(data_size);
	if (!result) {
		return NULL;
	}

	return memcpy(result, data, data_size);
}

char *sprintf_alloc(const char *fmt, ...)
{
	char *strp = NULL;
	va_list ap;

	va_start(ap, fmt);
	int ret = vasprintf(&strp, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		return NULL;
	}
	return strp;
}

char *strcdup(const char *s1, const char *s2)
{
	if (!s1 || !s2) {
		return NULL;
	}

	size_t s1len = strlen(s1);
	size_t s2len = strlen(s2);
	size_t nlen = s1len + s2len + 1;

	char* dst = malloc(nlen);
	if (dst == NULL) {
		return NULL;
	}

	memcpy(dst, s1, s1len);
	memcpy(dst + s1len, s2, s2len + 1);
	return dst;
}

char *strstrip(const char *str)
{
	// leading white-spaces
	const char *scan = str;
	while (is_space(scan[0])) {
		scan += 1;
	}

	// trailing white-spaces
	size_t len = strlen(scan);
	while (len > 0 && is_space(scan[len - 1])) {
		len -= 1;
	}

	char *trimmed = malloc(len + 1);
	if (!trimmed) {
		return NULL;
	}

	memcpy(trimmed, scan, len);
	trimmed[len] = '\0';

	return trimmed;
}

int const_time_memcmp(const void *s1, const void *s2, size_t n)
{
	volatile uint8_t equal = 0;

	for (size_t i = 0; i < n; i++) {
		equal |= ((uint8_t *)s1)[i] ^ ((uint8_t *)s2)[i];
	}

	return equal;
}

#if defined(USE_CUSTOM_MEMSET)
typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t volatile_memset = memset;
#endif

void *memzero(void *s, size_t n)
{
#if defined(HAVE_EXPLICIT_BZERO)	/* In OpenBSD since 5.5. */
					/* In FreeBSD since 11.0. */
					/* In glibc since 2.25. */
					/* In DragonFly BSD since 5.5. */
	explicit_bzero(s, n);
	return s;
#elif defined(HAVE_EXPLICIT_MEMSET)	/* In NetBSD since 7.0. */
	return explicit_memset(s, 0, n);
#elif defined(HAVE_GNUTLS_MEMSET)	/* In GnuTLS since 3.4.0. */
	gnutls_memset(s, 0, n);
	return s;
#else					/* Knot custom solution as a fallback. */
	/* Warning: the use of the return value is *probably* needed
	 * so as to avoid the volatile_memset() to be optimized out.
	 */
	return volatile_memset(s, 0, n);
#endif
}

static const char BIN_TO_HEX[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

char *bin_to_hex(const uint8_t *bin, size_t bin_len)
{
	if (bin == NULL) {
		return NULL;
	}

	size_t hex_size = bin_len * 2;
	char *hex = malloc(hex_size + 1);
	if (hex == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < bin_len; i++) {
		hex[2 * i]     = BIN_TO_HEX[bin[i] >> 4];
		hex[2 * i + 1] = BIN_TO_HEX[bin[i] & 0x0f];
	}
	hex[hex_size] = '\0';

	return hex;
}

/*!
 * Convert HEX character to numeric value (assumes valid input).
 */
static uint8_t hex_to_number(const char hex)
{
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	} else if (hex >= 'a' && hex <= 'f') {
		return hex - 'a' + 10;
	} else {
		assert(hex >= 'A' && hex <= 'F');
		return hex - 'A' + 10;
	}
}

uint8_t *hex_to_bin(const char *hex, size_t *out_len)
{
	if (hex == NULL || out_len == NULL) {
		return NULL;
	}

	size_t hex_len = strlen(hex);
	if (hex_len % 2 != 0) {
		return NULL;
	}

	size_t bin_len = hex_len / 2;
	uint8_t *bin = malloc(bin_len + 1);
	if (bin == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < bin_len; i++) {
		if (!is_xdigit(hex[2 * i]) || !is_xdigit(hex[2 * i + 1])) {
			free(bin);
			return NULL;
		}
		uint8_t high = hex_to_number(hex[2 * i]);
		uint8_t low  = hex_to_number(hex[2 * i + 1]);
		bin[i] = high << 4 | low;
	}

	*out_len = bin_len;

	return bin;
}
