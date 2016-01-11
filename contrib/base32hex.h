/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Base32hex implementation (RFC 4648).
 *
 * \note Input Base32hex string can contain a-v characters. These characters
 *       are considered as A-V equivalent.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Decodes text data using Base32hex.
 *
 * \note Input data needn't be terminated with '\0'.
 *
 * \note Input data must be continuous Base32hex string!
 *
 * \param in		Input text data.
 * \param in_len	Length of input string.
 * \param out		Output data buffer.
 * \param out_len	Size of output buffer.
 *
 * \retval >=0		length of output data.
 * \retval KNOT_E*	if error.
 */
int32_t base32hex_decode(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len);

/*! @} */
