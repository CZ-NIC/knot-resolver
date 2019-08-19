/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Common macros.
 */

#pragma once

#define ABS(x) ((x) < 0 ? -(x) : (x))
#ifndef MIN
/*! \brief Type-safe minimum macro. */
#define MIN(a, b) \
	__extension__({ \
		__typeof__ (a) _amin = (a); \
	 	__typeof__ (b) _bmin = (b); \
		_amin < _bmin ? _amin : _bmin; })

/*! \brief Type-safe maximum macro. */
#define MAX(a, b) \
	__extension__({ \
		__typeof__ (a) _amax = (a); \
		__typeof__ (b) _bmax = (b); \
		_amax > _bmax ? _amax : _bmax; })
#endif

#ifndef likely
/*! \brief Optimize for x to be true value. */
#define likely(x) __builtin_expect((x), 1)
#endif

#ifndef unlikely
/*! \brief Optimize for x to be false value. */
#define unlikely(x) __builtin_expect((x), 0)
#endif
