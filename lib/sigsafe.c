#include <stdarg.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "./sigsafe.h"

/*
	The sigsafe_append_TYPE functions convert value into NULL-terminated string,
	they take
		* dst: beginning of the output buffer,
		* dste: end of the output buffer (excl.),
		* ...
	and return ptr to final terminating '\0' within the buffer;
	the buffer has to contain space for at least the '\0', which is always written.
	The APPEND(TYPE, ...) macro calls the sigsafe_append_TYPE function and modifies dst variable
	to allow further appending.
*/

#define APPEND(type, ...) dst = sigsafe_append_ ## type (dst, dste, __VA_ARGS__)

/// Appends character multiple times (negative cnt works as zero).
char *sigsafe_append_char(char *dst, char *dste, char c, int cnt) {
	while ((dst < dste - 1) && (cnt-- > 0)) {
		*dst++ = c;
	}
	*dst = '\0';
	return dst;
}

/// Appends data of given length (NULL-terminating them).
char *sigsafe_append_data(char *dst, char *dste, const char *src, size_t len) {
	const size_t max_len = dste-dst-1;
	if (len > max_len) {
		len = max_len;
	}

	memcpy(dst, src, len);
	dst += len;
	*dst = '\0';
	return dst;
}

/// Appends string, possibly padded to given width.
char *sigsafe_append_str(char *dst, char *dste, int width, bool align_left, const char *str) {
	int len = strlen(str);
	if (!align_left) APPEND(char, ' ', width - len);
	APPEND(data, str, len);
	if (align_left)  APPEND(char, ' ', width - len);
	return dst;
}

/// Appends unsigned int in given numeral base, possibly padded to given width and preceeded with the given sign.
char *sigsafe_append_uint(char *dst, char *dste, int base, int width, char padding_char, char sign_char, unsigned val) {
	const char digits[] ="0123456789abcdef";
	char tmp[sizeof(val) * 8 / 3 + 1];  // just digits of the resulting number, not null-terminated
	char *sp = tmp + sizeof(tmp);
	char *se = sp;
	while ((val > 0) || (sp == se)) {
		*--sp = digits[val % base];
		val /= base;
		width--;
	}

	if (sign_char) {
		width--;
		if (padding_char == '0') {
			APPEND(char, sign_char, 1);
		}
	}
	APPEND(char, padding_char, width);
	if (sign_char && (padding_char != '0')) {
		APPEND(char, sign_char, 1);
	}

	return APPEND(data, sp, se-sp);
}

/// Appends signed int in given numeral base, possibly padded to given width.
char *sigsafe_append_int(char *dst, char *dste, int base, int width, char padding_char, int val) {
	char sign_char = 0;
	if (val < 0) {
		sign_char = '-';
		val *= -1;
	}
	return APPEND(uint, base, width, padding_char, sign_char, val);
}


/// Appends real number with given precision, possibly padded to given width.
char *sigsafe_append_double(char *dst, char *dste, int width, int precision, double val) {
	int sign = 1;
	if (val < 0) {
		val *= -1;
		sign = -1;
	}
	int64_t pmult = 1;
	for (int i = 0; i < precision; i++) {
		pmult *= 10;
	}
	int64_t vali = val * pmult + 0.5;  // NOLINT(bugprone-incorrect-roundings), just minor imprecisions
		// larger numbers, NaNs, ... are not handled
	APPEND(int, 10, width - precision - 1, ' ', sign * (vali / pmult));
	APPEND(char, '.', 1);
	APPEND(uint, 10, precision, '0', 0, (vali % pmult));
	return dst;
}

/// Find indices of maximal zero-filled gap in IPv6 (zeroes-end index is excl.)
static inline void sigsafe_inet6_longest_zeroes(uint8_t *ipv6, int *zb_out, int *ze_out) {
	*zb_out = -2; *ze_out = 0;  // nothing to be skipped
	int zb = 0, ze = 0;
	for (size_t i = 0; i < 16; i += 2) {
		if (!ipv6[i] && !ipv6[i+1]) {
			if (i == ze) {
				ze += 2;
			} else {
				if (ze - zb > *ze_out - *zb_out) {
					*zb_out = zb;
					*ze_out = ze;
				}
				zb = i; ze = i + 2;
			}
		}
	}
	if (ze - zb > *ze_out - *zb_out) {
		*zb_out = zb;
		*ze_out = ze;
	}
}

/// Appends network address containing AF_UNIX, AF_INET (with port), or AF_INET6 (with port).
char *sigsafe_append_sockaddr(char *dst, char *dste, struct sockaddr *addr) {
	if (!addr) {
		return APPEND(str, 0, false, "(null)");
	}
	switch (addr->sa_family) {
		case AF_UNIX:
			return APPEND(str, 0, false, ((struct sockaddr_un *)addr)->sun_path);
		case AF_INET: {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
			uint8_t *ipv4 = (uint8_t *)&(addr4->sin_addr);
			uint8_t *port = (uint8_t *)&(addr4->sin_port);
			for (int i = 0; i < 4; i++) {
				APPEND(uint, 10, 0, '0', 0, ipv4[i]);
				APPEND(char, "...#"[i], 1);
			}
			APPEND(uint, 10, 0, '0', 0, (port[0] << 8) | port[1]);
			return dst;
			};
		case AF_INET6: {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
			uint8_t *ipv6 = (uint8_t *)&(addr6->sin6_addr);
			uint8_t *port = (uint8_t *)&(addr6->sin6_port);
			int zb, ze;  // maximal zero-filled gap begin (incl.) and end (excl.)
			sigsafe_inet6_longest_zeroes(ipv6, &zb, &ze);
			for (int i = -!zb; i < 15; i++) {
				if (i == zb) i = ze - 1;  // after ':' (possibly for i=-1), skip sth. and continue with ':' (possibly for i=15)
				if (i%2) {
					APPEND(char, ':', 1);
				} else {
					APPEND(uint, 16, 0, '0', 0, (ipv6[i] << 8) | ipv6[i+1]);
				}
			}
			APPEND(char, '#', 1);
			APPEND(uint, 10, 0, '0', 0, (port[0] << 8) | port[1]);
			return dst;
			};
		case AF_UNSPEC:
			return APPEND(str, 0, false, "(unspec)");
		default:
			return APPEND(str, 0, false, "(unknown)");
	}
}

int sigsafe_format(char *str, size_t size, const char *fmt, ...) {
	char *dst = str;         // ptr just after the last written non-null character
	char *dste = str + size; // ptr just after str buffer
	va_list ap;
	va_start(ap, fmt);  // NOLINT, should be safe in GCC
	while (*fmt && (dste-dst > 1)) {
		if (*fmt != '%') {
			char *perc = strchr(fmt, '%');
			int len = perc ? perc - fmt : strlen(fmt);
			APPEND(data, fmt, len);
			fmt += len;
			continue;
		}
		fmt++;

		bool flag_zero = false;
		bool flag_left = false;
		while (true) {
			switch(*fmt) {
				case '0':
					flag_zero = true;
					fmt++;
					continue;
				case '-':
					flag_left = true;
					fmt++;
					continue;
				default:
					break;
				}
			break;
		}

		int width = 0;
		while (('0' <= *fmt) && (*fmt <= '9')) {
			width = width * 10 + *fmt - '0';
			fmt++;
		}

		int precision = 3;
		if (*fmt == '.') {
			fmt++;
			precision = 0;
			while (('0' <= *fmt) && (*fmt <= '9')) {
				precision = precision * 10 + *fmt - '0';
				fmt++;
			}
		}

		switch(*fmt) {
			case '%':
				APPEND(char, '%', 1);
				break;
			case 's':
				APPEND(str, width, flag_left,
					va_arg(ap, char *));                 // NOLINT, should be safe in GCC
				break;
			case 'x':
				APPEND(uint, 16, width, flag_zero ? '0' : ' ', 0,
					va_arg(ap, unsigned));               // NOLINT, should be safe in GCC
				break;
			case 'u':
				APPEND(uint, 10, width, flag_zero ? '0' : ' ', 0,
					va_arg(ap, unsigned));               // NOLINT, should be safe in GCC
				break;
			case 'i':
				APPEND(int, 10, width, flag_zero ? '0' : ' ',
					va_arg(ap, int));                    // NOLINT, should be safe in GCC
				break;
			case 'f':
				APPEND(double, width, precision,
					va_arg(ap, double));                 // NOLINT, should be safe in GCC
				break;
			case 'r':
				APPEND(sockaddr,
					va_arg(ap, void *));                 // NOLINT, should be safe in GCC
				break;
			default:
				APPEND(str, 0, false, "[ERR]");
				break;
		}
		fmt++;
	}
	va_end(ap);  // NOLINT, should be safe in GCC
	return dst-str;
}
