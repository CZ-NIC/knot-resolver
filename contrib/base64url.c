/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/base64url.h"
#include "libknot/errcode.h"

#include <stdlib.h>
#include <stdint.h>

/*! \brief Maximal length of binary input to Base64url encoding. */
#define MAX_BIN_DATA_LEN	((INT32_MAX / 4) * 3)

/*! \brief Base64url padding character. */
static const uint8_t base64url_pad = '\0';
/*! \brief Base64 alphabet. */
static const uint8_t base64url_enc[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*! \brief Indicates bad Base64 character. */
#define KO	255
/*! \brief Indicates Base64 padding character. */
#define PD	 64

/*! \brief Transformation and validation table for decoding Base64. */
static const uint8_t base64url_dec[256] = {
	[  0] = PD, [ 43] = KO, ['V'] = 21, [129] = KO, [172] = KO, [215] = KO,
	[  1] = KO, [ 44] = KO, ['W'] = 22, [130] = KO, [173] = KO, [216] = KO,
	[  2] = KO, ['-'] = 62, ['X'] = 23, [131] = KO, [174] = KO, [217] = KO,
	[  3] = KO, [ 46] = KO, ['Y'] = 24, [132] = KO, [175] = KO, [218] = KO,
	[  4] = KO, [ 47] = KO, ['Z'] = 25, [133] = KO, [176] = KO, [219] = KO,
	[  5] = KO, ['0'] = 52, [ 91] = KO, [134] = KO, [177] = KO, [220] = KO,
	[  6] = KO, ['1'] = 53, [ 92] = KO, [135] = KO, [178] = KO, [221] = KO,
	[  7] = KO, ['2'] = 54, [ 93] = KO, [136] = KO, [179] = KO, [222] = KO,
	[  8] = KO, ['3'] = 55, [ 94] = KO, [137] = KO, [180] = KO, [223] = KO,
	[  9] = KO, ['4'] = 56, ['_'] = 63, [138] = KO, [181] = KO, [224] = KO,
	[ 10] = KO, ['5'] = 57, [ 96] = KO, [139] = KO, [182] = KO, [225] = KO,
	[ 11] = KO, ['6'] = 58, ['a'] = 26, [140] = KO, [183] = KO, [226] = KO,
	[ 12] = KO, ['7'] = 59, ['b'] = 27, [141] = KO, [184] = KO, [227] = KO,
	[ 13] = KO, ['8'] = 60, ['c'] = 28, [142] = KO, [185] = KO, [228] = KO,
	[ 14] = KO, ['9'] = 61, ['d'] = 29, [143] = KO, [186] = KO, [229] = KO,
	[ 15] = KO, [ 58] = KO, ['e'] = 30, [144] = KO, [187] = KO, [230] = KO,
	[ 16] = KO, [ 59] = KO, ['f'] = 31, [145] = KO, [188] = KO, [231] = KO,
	[ 17] = KO, [ 60] = KO, ['g'] = 32, [146] = KO, [189] = KO, [232] = KO,
	[ 18] = KO, [ 61] = KO, ['h'] = 33, [147] = KO, [190] = KO, [233] = KO,
	[ 19] = KO, [ 62] = KO, ['i'] = 34, [148] = KO, [191] = KO, [234] = KO,
	[ 20] = KO, [ 63] = KO, ['j'] = 35, [149] = KO, [192] = KO, [235] = KO,
	[ 21] = KO, [ 64] = KO, ['k'] = 36, [150] = KO, [193] = KO, [236] = KO,
	[ 22] = KO, ['A'] =  0, ['l'] = 37, [151] = KO, [194] = KO, [237] = KO,
	[ 23] = KO, ['B'] =  1, ['m'] = 38, [152] = KO, [195] = KO, [238] = KO,
	[ 24] = KO, ['C'] =  2, ['n'] = 39, [153] = KO, [196] = KO, [239] = KO,
	[ 25] = KO, ['D'] =  3, ['o'] = 40, [154] = KO, [197] = KO, [240] = KO,
	[ 26] = KO, ['E'] =  4, ['p'] = 41, [155] = KO, [198] = KO, [241] = KO,
	[ 27] = KO, ['F'] =  5, ['q'] = 42, [156] = KO, [199] = KO, [242] = KO,
	[ 28] = KO, ['G'] =  6, ['r'] = 43, [157] = KO, [200] = KO, [243] = KO,
	[ 29] = KO, ['H'] =  7, ['s'] = 44, [158] = KO, [201] = KO, [244] = KO,
	[ 30] = KO, ['I'] =  8, ['t'] = 45, [159] = KO, [202] = KO, [245] = KO,
	[ 31] = KO, ['J'] =  9, ['u'] = 46, [160] = KO, [203] = KO, [246] = KO,
	[ 32] = KO, ['K'] = 10, ['v'] = 47, [161] = KO, [204] = KO, [247] = KO,
	[ 33] = KO, ['L'] = 11, ['w'] = 48, [162] = KO, [205] = KO, [248] = KO,
	[ 34] = KO, ['M'] = 12, ['x'] = 49, [163] = KO, [206] = KO, [249] = KO,
	[ 35] = KO, ['N'] = 13, ['y'] = 50, [164] = KO, [207] = KO, [250] = KO,
	[ 36] = KO, ['O'] = 14, ['z'] = 51, [165] = KO, [208] = KO, [251] = KO,
	[ 37] = KO, ['P'] = 15, [123] = KO, [166] = KO, [209] = KO, [252] = KO,
	[ 38] = KO, ['Q'] = 16, [124] = KO, [167] = KO, [210] = KO, [253] = KO,
	[ 39] = KO, ['R'] = 17, [125] = KO, [168] = KO, [211] = KO, [254] = KO,
	[ 40] = KO, ['S'] = 18, [126] = KO, [169] = KO, [212] = KO, [255] = KO,
	[ 41] = KO, ['T'] = 19, [127] = KO, [170] = KO, [213] = KO,
	[ 42] = KO, ['U'] = 20, [128] = KO, [171] = KO, [214] = KO,
};

int32_t kr_base64url_encode(const uint8_t  *in,
                      const uint32_t in_len,
                      uint8_t        *out,
                      const uint32_t out_len)
{
	// Checking inputs.
	if (in == NULL || out == NULL) {
		return KNOT_EINVAL;
	}
	if (in_len > MAX_BIN_DATA_LEN || out_len < ((in_len + 2) / 3) * 4) {
		return KNOT_ERANGE;
	}

	uint8_t		rest_len = in_len % 3;
	const uint8_t	*stop = in + in_len - rest_len;
	uint8_t		*text = out;

	// Encoding loop takes 3 bytes and creates 4 characters.
	while (in < stop) {
		text[0] = base64url_enc[in[0] >> 2];
		text[1] = base64url_enc[(in[0] & 0x03) << 4 | in[1] >> 4];
		text[2] = base64url_enc[(in[1] & 0x0F) << 2 | in[2] >> 6];
		text[3] = base64url_enc[in[2] & 0x3F];
		text += 4;
		in += 3;
	}

	// Processing of padding, if any.
	switch (rest_len) {
	case 2:
		text[0] = base64url_enc[in[0] >> 2];
		text[1] = base64url_enc[(in[0] & 0x03) << 4 | in[1] >> 4];
		text[2] = base64url_enc[(in[1] & 0x0F) << 2];
		text[3] = base64url_pad;
		text += 3;
		break;
	case 1:
		text[0] = base64url_enc[in[0] >> 2];
		text[1] = base64url_enc[(in[0] & 0x03) << 4];
		text[2] = base64url_pad;
		text[3] = base64url_pad;
		text += 2;
		break;
	}
	return (text - out);
}

int32_t kr_base64url_encode_alloc(const uint8_t  *in,
                            const uint32_t in_len,
                            uint8_t        **out)
{
	// Checking inputs.
	if (out == NULL) {
		return KNOT_EINVAL;
	}
	if (in_len > MAX_BIN_DATA_LEN) {
		return KNOT_ERANGE;
	}

	// Compute output buffer length.
	uint32_t out_len = ((in_len + 2) / 3) * 4;

	// Allocate output buffer.
	*out = malloc(out_len);
	if (*out == NULL) {
		return KNOT_ENOMEM;
	}

	// Encode data.
	int32_t ret = kr_base64url_encode(in, in_len, *out, out_len);
	if (ret < 0) {
		free(*out);
		*out = NULL;
	}

	return ret;
}

int32_t kr_base64url_decode(const uint8_t  *in,
                      const uint32_t in_len,
                      uint8_t        *out,
                      const uint32_t out_len)
{
	// Checking inputs.
	if (in == NULL || out == NULL) {
		return KNOT_EINVAL;
	}
	if (in_len > INT32_MAX || out_len < ((in_len + 3) / 4) * 3) {
		return KNOT_ERANGE;
	}

	const uint8_t	*stop = in + in_len;
	uint8_t		*bin = out;
	uint8_t		pad_len = 0;
	uint8_t		c1, c2, c3, c4;

	// Decoding loop takes 4 characters and creates 3 bytes.
	while (in < stop) {
		// Filling and transforming 4 Base64 chars.
		c1 =                   base64url_dec[in[0]]     ;
		c2 = (in + 1 < stop) ? base64url_dec[in[1]] : PD;
		c3 = (in + 2 < stop) ? base64url_dec[in[2]] : PD;
		c4 = (in + 3 < stop) ? base64url_dec[in[3]] : PD;

		// Check 4. char if is bad or padding.
		if (c4 >= PD) {
			if (c4 == PD && pad_len == 0) {
				pad_len = 1;
			} else {
				return KNOT_BASE64_ECHAR;
			}
		}

		// Check 3. char if is bad or padding.
		if (c3 >= PD) {
			if (c3 == PD && pad_len == 1) {
				pad_len = 2;
			} else {
				return KNOT_BASE64_ECHAR;
			}
		}

		// Check 1. and 2. chars if are not padding.
		if (c2 >= PD || c1 >= PD) {
			return KNOT_BASE64_ECHAR;
		}

		// Computing of output data based on padding length.
		switch (pad_len) {
		case 0:
			bin[2] = (c3 << 6) + c4;
			// FALLTHROUGH
		case 1:
			bin[1] = (c2 << 4) + (c3 >> 2);
			// FALLTHROUGH
		case 2:
			bin[0] = (c1 << 2) + (c2 >> 4);
		}

		// Update output end.
		switch (pad_len) {
		case 0:
			bin += 3;
			break;
		case 1:
			bin += 2;
			break;
		case 2:
			bin += 1;
			break;
		}

		in += 4;
	}

	return (bin - out);
}

int32_t kr_base64url_decode_alloc(const uint8_t  *in,
                            const uint32_t in_len,
                            uint8_t        **out)
{
	// Checking inputs.
	if (out == NULL) {
		return KNOT_EINVAL;
	}

	// Compute output buffer length.
	uint32_t out_len = ((in_len + 3) / 4) * 3;

	// Allocate output buffer.
	*out = malloc(out_len);
	if (*out == NULL) {
		return KNOT_ENOMEM;
	}

	// Decode data.
	int32_t ret = kr_base64url_decode(in, in_len, *out, out_len);
	if (ret < 0) {
		free(*out);
		*out = NULL;
	}

	return ret;
}
