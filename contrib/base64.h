/*  Copyright (C) 2011-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
/*!
 * \file
 *
 * \brief Base64 implementation (RFC 4648).
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Encodes binary data using Base64.
 *
 * \note Output data buffer contains Base64 text string which isn't
 *       terminated with '\0'!
 *
 * \param in		Input binary data.
 * \param in_len	Length of input data.
 * \param out		Output data buffer.
 * \param out_len	Size of output buffer.
 *
 * \retval >=0		length of output string.
 * \retval KNOT_E*	if error.
 */
int32_t kr_base64_encode(const uint8_t  *in,
                      const uint32_t in_len,
                      uint8_t        *out,
                      const uint32_t out_len);

/*!
 * \brief Encodes binary data using Base64 and output stores to own buffer.
 *
 * \note Output data buffer contains Base64 text string which isn't
 *       terminated with '\0'!
 *
 * \note Output buffer should be deallocated after use.
 *
 * \param in		Input binary data.
 * \param in_len	Length of input data.
 * \param out		Output data buffer.
 *
 * \retval >=0		length of output string.
 * \retval KNOT_E*	if error.
 */
int32_t kr_base64_encode_alloc(const uint8_t  *in,
                            const uint32_t in_len,
                            uint8_t        **out);

/*!
 * \brief Decodes text data using Base64.
 *
 * \note Input data needn't be terminated with '\0'.
 *
 * \note Input data must be continuous Base64 string!
 *
 * \param in		Input text data.
 * \param in_len	Length of input string.
 * \param out		Output data buffer.
 * \param out_len	Size of output buffer.
 *
 * \retval >=0		length of output data.
 * \retval KNOT_E*	if error.
 */
int32_t kr_base64_decode(const uint8_t  *in,
                      const uint32_t in_len,
                      uint8_t        *out,
                      const uint32_t out_len);

/*!
 * \brief Decodes text data using Base64 and output stores to own buffer.
 *
 * \note Input data needn't be terminated with '\0'.
 *
 * \note Input data must be continuous Base64 string!
 *
 * \note Output buffer should be deallocated after use.
 *
 * \param in		Input text data.
 * \param in_len	Length of input string.
 * \param out		Output data buffer.
 *
 * \retval >=0		length of output data.
 * \retval KNOT_E*	if error.
 */
int32_t kr_base64_decode_alloc(const uint8_t  *in,
                            const uint32_t in_len,
                            uint8_t        **out);

/*! @} */
