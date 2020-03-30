/*  Copyright (C) 2011-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "base32hex.h"

#include <stdlib.h>
#include <stdint.h>

/*! \brief Maximal length of binary input to Base32hex encoding. */
#define MAX_BIN_DATA_LEN	((INT32_MAX / 8) * 5)

/*! \brief Base32hex padding character. */
static const uint8_t base32hex_pad = '=';
/*! \brief Base32hex alphabet.  Beware: original code was upper-case. */
static const uint8_t base32hex_enc[] = "0123456789abcdefghijklmnopqrstuv";

/*! \brief Indicates bad Base32hex character. */
#define KO	255
/*! \brief Indicates Base32hex padding character. */
#define PD	 32

/*! \brief Transformation and validation table for decoding Base32hex. */
static const uint8_t base32hex_dec[256] = {
	[  0] = KO, [ 43] = KO, ['V'] = 31, [129] = KO, [172] = KO, [215] = KO,
	[  1] = KO, [ 44] = KO, ['W'] = KO, [130] = KO, [173] = KO, [216] = KO,
	[  2] = KO, [ 45] = KO, ['X'] = KO, [131] = KO, [174] = KO, [217] = KO,
	[  3] = KO, [ 46] = KO, ['Y'] = KO, [132] = KO, [175] = KO, [218] = KO,
	[  4] = KO, [ 47] = KO, ['Z'] = KO, [133] = KO, [176] = KO, [219] = KO,
	[  5] = KO, ['0'] =  0, [ 91] = KO, [134] = KO, [177] = KO, [220] = KO,
	[  6] = KO, ['1'] =  1, [ 92] = KO, [135] = KO, [178] = KO, [221] = KO,
	[  7] = KO, ['2'] =  2, [ 93] = KO, [136] = KO, [179] = KO, [222] = KO,
	[  8] = KO, ['3'] =  3, [ 94] = KO, [137] = KO, [180] = KO, [223] = KO,
	[  9] = KO, ['4'] =  4, [ 95] = KO, [138] = KO, [181] = KO, [224] = KO,
	[ 10] = KO, ['5'] =  5, [ 96] = KO, [139] = KO, [182] = KO, [225] = KO,
	[ 11] = KO, ['6'] =  6, ['a'] = 10, [140] = KO, [183] = KO, [226] = KO,
	[ 12] = KO, ['7'] =  7, ['b'] = 11, [141] = KO, [184] = KO, [227] = KO,
	[ 13] = KO, ['8'] =  8, ['c'] = 12, [142] = KO, [185] = KO, [228] = KO,
	[ 14] = KO, ['9'] =  9, ['d'] = 13, [143] = KO, [186] = KO, [229] = KO,
	[ 15] = KO, [ 58] = KO, ['e'] = 14, [144] = KO, [187] = KO, [230] = KO,
	[ 16] = KO, [ 59] = KO, ['f'] = 15, [145] = KO, [188] = KO, [231] = KO,
	[ 17] = KO, [ 60] = KO, ['g'] = 16, [146] = KO, [189] = KO, [232] = KO,
	[ 18] = KO, ['='] = PD, ['h'] = 17, [147] = KO, [190] = KO, [233] = KO,
	[ 19] = KO, [ 62] = KO, ['i'] = 18, [148] = KO, [191] = KO, [234] = KO,
	[ 20] = KO, [ 63] = KO, ['j'] = 19, [149] = KO, [192] = KO, [235] = KO,
	[ 21] = KO, [ 64] = KO, ['k'] = 20, [150] = KO, [193] = KO, [236] = KO,
	[ 22] = KO, ['A'] = 10, ['l'] = 21, [151] = KO, [194] = KO, [237] = KO,
	[ 23] = KO, ['B'] = 11, ['m'] = 22, [152] = KO, [195] = KO, [238] = KO,
	[ 24] = KO, ['C'] = 12, ['n'] = 23, [153] = KO, [196] = KO, [239] = KO,
	[ 25] = KO, ['D'] = 13, ['o'] = 24, [154] = KO, [197] = KO, [240] = KO,
	[ 26] = KO, ['E'] = 14, ['p'] = 25, [155] = KO, [198] = KO, [241] = KO,
	[ 27] = KO, ['F'] = 15, ['q'] = 26, [156] = KO, [199] = KO, [242] = KO,
	[ 28] = KO, ['G'] = 16, ['r'] = 27, [157] = KO, [200] = KO, [243] = KO,
	[ 29] = KO, ['H'] = 17, ['s'] = 28, [158] = KO, [201] = KO, [244] = KO,
	[ 30] = KO, ['I'] = 18, ['t'] = 29, [159] = KO, [202] = KO, [245] = KO,
	[ 31] = KO, ['J'] = 19, ['u'] = 30, [160] = KO, [203] = KO, [246] = KO,
	[ 32] = KO, ['K'] = 20, ['v'] = 31, [161] = KO, [204] = KO, [247] = KO,
	[ 33] = KO, ['L'] = 21, ['w'] = KO, [162] = KO, [205] = KO, [248] = KO,
	[ 34] = KO, ['M'] = 22, ['x'] = KO, [163] = KO, [206] = KO, [249] = KO,
	[ 35] = KO, ['N'] = 23, ['y'] = KO, [164] = KO, [207] = KO, [250] = KO,
	[ 36] = KO, ['O'] = 24, ['z'] = KO, [165] = KO, [208] = KO, [251] = KO,
	[ 37] = KO, ['P'] = 25, [123] = KO, [166] = KO, [209] = KO, [252] = KO,
	[ 38] = KO, ['Q'] = 26, [124] = KO, [167] = KO, [210] = KO, [253] = KO,
	[ 39] = KO, ['R'] = 27, [125] = KO, [168] = KO, [211] = KO, [254] = KO,
	[ 40] = KO, ['S'] = 28, [126] = KO, [169] = KO, [212] = KO, [255] = KO,
	[ 41] = KO, ['T'] = 29, [127] = KO, [170] = KO, [213] = KO,
	[ 42] = KO, ['U'] = 30, [128] = KO, [171] = KO, [214] = KO,
};

int32_t base32hex_decode(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len)
{
	// Checking inputs.
	if (in == NULL || out == NULL) {
		return -1;
	}
	if (in_len > INT32_MAX || out_len < ((in_len + 7) / 8) * 5) {
		return -1;
	}
	if ((in_len % 8) != 0) {
		return -1;
	}

	const uint8_t	*stop = in + in_len;
	uint8_t		*bin = out;
	uint8_t		pad_len = 0;
	uint8_t		c1, c2, c3, c4, c5, c6, c7, c8;

	// Decoding loop takes 8 characters and creates 5 bytes.
	while (in < stop) {
		// Filling and transforming 8 Base32hex chars.
		c1 = base32hex_dec[in[0]];
		c2 = base32hex_dec[in[1]];
		c3 = base32hex_dec[in[2]];
		c4 = base32hex_dec[in[3]];
		c5 = base32hex_dec[in[4]];
		c6 = base32hex_dec[in[5]];
		c7 = base32hex_dec[in[6]];
		c8 = base32hex_dec[in[7]];

		// Check 8. char if is bad or padding.
		if (c8 >= PD) {
			if (c8 == PD && pad_len == 0) {
				pad_len = 1;
			} else {
				return -1;
			}
		}

		// Check 7. char if is bad or padding (if so, 6. must be too).
		if (c7 >= PD) {
			if (c7 == PD && c6 == PD && pad_len == 1) {
				pad_len = 3;
			} else {
				return -1;
			}
		}

		// Check 6. char if is bad or padding.
		if (c6 >= PD) {
			if (!(c6 == PD && pad_len == 3)) {
				return -1;
			}
		}

		// Check 5. char if is bad or padding.
		if (c5 >= PD) {
			if (c5 == PD && pad_len == 3) {
				pad_len = 4;
			} else {
				return -1;
			}
		}

		// Check 4. char if is bad or padding (if so, 3. must be too).
		if (c4 >= PD) {
			if (c4 == PD && c3 == PD && pad_len == 4) {
				pad_len = 6;
			} else {
				return -1;
			}
		}

		// Check 3. char if is bad or padding.
		if (c3 >= PD) {
			if (!(c3 == PD && pad_len == 6)) {
				return -1;
			}
		}

		// 1. and 2. chars must not be padding.
		if (c2 >= PD || c1 >= PD) {
			return -1;
		}

		// Computing of output data based on padding length.
		switch (pad_len) {
		case 0:
			bin[4] = (c7 << 5) + c8;
		case 1:
			bin[3] = (c5 << 7) + (c6 << 2) + (c7 >> 3);
		case 3:
			bin[2] = (c4 << 4) + (c5 >> 1);
		case 4:
			bin[1] = (c2 << 6) + (c3 << 1) + (c4 >> 4);
		case 6:
			bin[0] = (c1 << 3) + (c2 >> 2);
		}

		// Update output end.
		switch (pad_len) {
		case 0:
			bin += 5;
			break;
		case 1:
			bin += 4;
			break;
		case 3:
			bin += 3;
			break;
		case 4:
			bin += 2;
			break;
		case 6:
			bin += 1;
			break;
		}

		in += 8;
	}

	return (bin - out);
}

int32_t base32hex_encode(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len)
{
	// Checking inputs.
	if (in == NULL || out == NULL) {
		return -1;
	}
	if (in_len > MAX_BIN_DATA_LEN || out_len < ((in_len + 4) / 5) * 8) {
		return -1;
	}

	uint8_t		rest_len = in_len % 5;
	const uint8_t	*stop = in + in_len - rest_len;
	uint8_t		*text = out;

	// Encoding loop takes 5 bytes and creates 8 characters.
	while (in < stop) {
		text[0] = base32hex_enc[in[0] >> 3];
		text[1] = base32hex_enc[(in[0] & 0x07) << 2 | in[1] >> 6];
		text[2] = base32hex_enc[(in[1] & 0x3E) >> 1];
		text[3] = base32hex_enc[(in[1] & 0x01) << 4 | in[2] >> 4];
		text[4] = base32hex_enc[(in[2] & 0x0F) << 1 | in[3] >> 7];
		text[5] = base32hex_enc[(in[3] & 0x7C) >> 2];
		text[6] = base32hex_enc[(in[3] & 0x03) << 3 | in[4] >> 5];
		text[7] = base32hex_enc[in[4] & 0x1F];
		text += 8;
		in += 5;
	}

	// Processing of padding, if any.
	switch (rest_len) {
	case 4:
		text[0] = base32hex_enc[in[0] >> 3];
		text[1] = base32hex_enc[(in[0] & 0x07) << 2 | in[1] >> 6];
		text[2] = base32hex_enc[(in[1] & 0x3E) >> 1];
		text[3] = base32hex_enc[(in[1] & 0x01) << 4 | in[2] >> 4];
		text[4] = base32hex_enc[(in[2] & 0x0F) << 1 | in[3] >> 7];
		text[5] = base32hex_enc[(in[3] & 0x7C) >> 2];
		text[6] = base32hex_enc[(in[3] & 0x03) << 3];
		text[7] = base32hex_pad;
		text += 8;
		break;
	case 3:
		text[0] = base32hex_enc[in[0] >> 3];
		text[1] = base32hex_enc[(in[0] & 0x07) << 2 | in[1] >> 6];
		text[2] = base32hex_enc[(in[1] & 0x3E) >> 1];
		text[3] = base32hex_enc[(in[1] & 0x01) << 4 | in[2] >> 4];
		text[4] = base32hex_enc[(in[2] & 0x0F) << 1];
		text[5] = base32hex_pad;
		text[6] = base32hex_pad;
		text[7] = base32hex_pad;
		text += 8;
		break;
	case 2:
		text[0] = base32hex_enc[in[0] >> 3];
		text[1] = base32hex_enc[(in[0] & 0x07) << 2 | in[1] >> 6];
		text[2] = base32hex_enc[(in[1] & 0x3E) >> 1];
		text[3] = base32hex_enc[(in[1] & 0x01) << 4];
		text[4] = base32hex_pad;
		text[5] = base32hex_pad;
		text[6] = base32hex_pad;
		text[7] = base32hex_pad;
		text += 8;
		break;
	case 1:
		text[0] = base32hex_enc[in[0] >> 3];
		text[1] = base32hex_enc[(in[0] & 0x07) << 2];
		text[2] = base32hex_pad;
		text[3] = base32hex_pad;
		text[4] = base32hex_pad;
		text[5] = base32hex_pad;
		text[6] = base32hex_pad;
		text[7] = base32hex_pad;
		text += 8;
		break;
	}

	return (text - out);
}
