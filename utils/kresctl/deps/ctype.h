/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*!
 * \brief Locale-independent ctype functions.
 */

#pragma once

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

enum {
	CT_DIGIT = 1 << 0,
	CT_UPPER = 1 << 1,
	CT_LOWER = 1 << 2,
	CT_XDIGT = 1 << 3,
	CT_PUNCT = 1 << 4,
	CT_PRINT = 1 << 5,
	CT_SPACE = 1 << 6,
};

static const uint8_t char_mask[256] = {
	// 0 - 8
	['\t'] = CT_SPACE,
	['\n'] = CT_SPACE,
	['\v'] = CT_SPACE,
	['\f'] = CT_SPACE,
	['\r'] = CT_SPACE,
	// 14 - 31
	[' ']  = CT_PRINT | CT_SPACE,

	['!']  = CT_PRINT | CT_PUNCT,
	['"']  = CT_PRINT | CT_PUNCT,
	['#']  = CT_PRINT | CT_PUNCT,
	['$']  = CT_PRINT | CT_PUNCT,
	['%']  = CT_PRINT | CT_PUNCT,
	['&']  = CT_PRINT | CT_PUNCT,
	['\''] = CT_PRINT | CT_PUNCT,
	['(']  = CT_PRINT | CT_PUNCT,
	[')']  = CT_PRINT | CT_PUNCT,
	['*']  = CT_PRINT | CT_PUNCT,
	['+']  = CT_PRINT | CT_PUNCT,
	[',']  = CT_PRINT | CT_PUNCT,
	['-']  = CT_PRINT | CT_PUNCT,
	['.']  = CT_PRINT | CT_PUNCT,
	['/']  = CT_PRINT | CT_PUNCT,

	['0']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['1']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['2']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['3']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['4']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['5']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['6']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['7']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['8']  = CT_PRINT | CT_DIGIT | CT_XDIGT,
	['9']  = CT_PRINT | CT_DIGIT | CT_XDIGT,

	[':']  = CT_PRINT | CT_PUNCT,
	[';']  = CT_PRINT | CT_PUNCT,
	['<']  = CT_PRINT | CT_PUNCT,
	['=']  = CT_PRINT | CT_PUNCT,
	['>']  = CT_PRINT | CT_PUNCT,
	['?']  = CT_PRINT | CT_PUNCT,
	['@']  = CT_PRINT | CT_PUNCT,

	['A']  = CT_PRINT | CT_UPPER | CT_XDIGT,
	['B']  = CT_PRINT | CT_UPPER | CT_XDIGT,
	['C']  = CT_PRINT | CT_UPPER | CT_XDIGT,
	['D']  = CT_PRINT | CT_UPPER | CT_XDIGT,
	['E']  = CT_PRINT | CT_UPPER | CT_XDIGT,
	['F']  = CT_PRINT | CT_UPPER | CT_XDIGT,
	['G']  = CT_PRINT | CT_UPPER,
	['H']  = CT_PRINT | CT_UPPER,
	['I']  = CT_PRINT | CT_UPPER,
	['J']  = CT_PRINT | CT_UPPER,
	['K']  = CT_PRINT | CT_UPPER,
	['L']  = CT_PRINT | CT_UPPER,
	['M']  = CT_PRINT | CT_UPPER,
	['N']  = CT_PRINT | CT_UPPER,
	['O']  = CT_PRINT | CT_UPPER,
	['P']  = CT_PRINT | CT_UPPER,
	['Q']  = CT_PRINT | CT_UPPER,
	['R']  = CT_PRINT | CT_UPPER,
	['S']  = CT_PRINT | CT_UPPER,
	['T']  = CT_PRINT | CT_UPPER,
	['U']  = CT_PRINT | CT_UPPER,
	['V']  = CT_PRINT | CT_UPPER,
	['W']  = CT_PRINT | CT_UPPER,
	['X']  = CT_PRINT | CT_UPPER,
	['Y']  = CT_PRINT | CT_UPPER,
	['Z']  = CT_PRINT | CT_UPPER,

	['[']  = CT_PRINT | CT_PUNCT,
	['\\'] = CT_PRINT | CT_PUNCT,
	[']']  = CT_PRINT | CT_PUNCT,
	['^']  = CT_PRINT | CT_PUNCT,
	['_']  = CT_PRINT | CT_PUNCT,
	['`']  = CT_PRINT | CT_PUNCT,

	['a']  = CT_PRINT | CT_LOWER | CT_XDIGT,
	['b']  = CT_PRINT | CT_LOWER | CT_XDIGT,
	['c']  = CT_PRINT | CT_LOWER | CT_XDIGT,
	['d']  = CT_PRINT | CT_LOWER | CT_XDIGT,
	['e']  = CT_PRINT | CT_LOWER | CT_XDIGT,
	['f']  = CT_PRINT | CT_LOWER | CT_XDIGT,
	['g']  = CT_PRINT | CT_LOWER,
	['h']  = CT_PRINT | CT_LOWER,
	['i']  = CT_PRINT | CT_LOWER,
	['j']  = CT_PRINT | CT_LOWER,
	['k']  = CT_PRINT | CT_LOWER,
	['l']  = CT_PRINT | CT_LOWER,
	['m']  = CT_PRINT | CT_LOWER,
	['n']  = CT_PRINT | CT_LOWER,
	['o']  = CT_PRINT | CT_LOWER,
	['p']  = CT_PRINT | CT_LOWER,
	['q']  = CT_PRINT | CT_LOWER,
	['r']  = CT_PRINT | CT_LOWER,
	['s']  = CT_PRINT | CT_LOWER,
	['t']  = CT_PRINT | CT_LOWER,
	['u']  = CT_PRINT | CT_LOWER,
	['v']  = CT_PRINT | CT_LOWER,
	['w']  = CT_PRINT | CT_LOWER,
	['x']  = CT_PRINT | CT_LOWER,
	['y']  = CT_PRINT | CT_LOWER,
	['z']  = CT_PRINT | CT_LOWER,

	['{']  = CT_PRINT | CT_PUNCT,
	['|']  = CT_PRINT | CT_PUNCT,
	['}']  = CT_PRINT | CT_PUNCT,
	['~']  = CT_PRINT | CT_PUNCT,
	// 127 - 255
};

static inline bool is_alnum(uint8_t c)
{
	return char_mask[c] & (CT_DIGIT | CT_UPPER | CT_LOWER);
}

static inline bool is_alpha(uint8_t c)
{
	return char_mask[c] & (CT_UPPER | CT_LOWER);
}

static inline bool is_digit(uint8_t c)
{
	return char_mask[c] & CT_DIGIT;
}

static inline bool is_xdigit(uint8_t c)
{
	return char_mask[c] & CT_XDIGT;
}

static inline bool is_lower(uint8_t c)
{
	return char_mask[c] & CT_LOWER;
}

static inline bool is_upper(uint8_t c)
{
	return char_mask[c] & CT_UPPER;
}

static inline bool is_print(uint8_t c)
{
	return char_mask[c] & CT_PRINT;
}

static inline bool is_punct(uint8_t c)
{
	return char_mask[c] & CT_PUNCT;
}

static inline bool is_space(uint8_t c)
{
	return char_mask[c] & CT_SPACE;
}
