/*  Copyright (C) 2011-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
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


/*!
 * \brief Encodes binary data using Base32hex.  Lower case is used!
 *
 * \note Output data buffer contains Base32hex text string which isn't
 *       terminated with '\0'!
 *
 * \param in		Input binary data.
 * \param in_len	Length of input data.
 * \param out		Output data buffer.
 * \param out_len	Size of output buffer.
 *
 * \retval >=0		length of output string.
 * \retval <0		if error.
 */
int32_t base32hex_encode(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len);

/*! @} */
