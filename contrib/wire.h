/*  Copyright (C) 2011-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */
/*!
 * \file
 *
 * \brief Wire integer operations.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <stdint.h>
#include <string.h>

#if defined(__linux__) || defined(__gnu_hurd__) || \
    (defined(__FreeBSD_kernel__) && defined(__GLIBC__))
#       include <endian.h>
#  ifndef be64toh
#       include <arpa/inet.h>
#       include <byteswap.h>
#    if BYTE_ORDER == LITTLE_ENDIAN
#       define be16toh(x) ntohs(x)
#       define be32toh(x) ntohl(x)
#       define be64toh(x) bswap_64 (x)
#       define le16toh(x) (x)
#       define le32toh(x) (x)
#       define le64toh(x) (x)
#    else
#       define be16toh(x) (x)
#       define be32toh(x) (x)
#       define be64toh(x) (x)
#       define le16toh(x) ntohs(x)
#       define le32toh(x) ntohl(x)
#       define le64toh(x) bswap_64 (x)
#    endif
#  endif
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#       include <sys/endian.h>
#elif defined(__OpenBSD__)
#       include <endian.h>
#elif defined(__APPLE__)
#       include <libkern/OSByteOrder.h>
#       define be16toh(x) OSSwapBigToHostInt16(x)
#       define be32toh(x) OSSwapBigToHostInt32(x)
#       define be64toh(x) OSSwapBigToHostInt64(x)
#       define htobe16(x) OSSwapHostToBigInt16(x)
#       define htobe32(x) OSSwapHostToBigInt32(x)
#       define htobe64(x) OSSwapHostToBigInt64(x)
#       define le16toh(x) OSSwapLittleToHostInt16(x)
#       define le32toh(x) OSSwapLittleToHostInt32(x)
#       define le64toh(x) OSSwapLittleToHostInt64(x)
#       define htole16(x) OSSwapHostToLittleInt16(x)
#       define htole32(x) OSSwapHostToLittleInt32(x)
#       define htole64(x) OSSwapHostToLittleInt64(x)
#endif

/*!
 * \brief Reads 2 bytes from the wireformat data.
 *
 * \param pos Data to read the 2 bytes from.
 *
 * \return The 2 bytes read, in host byte order.
 */
inline static uint16_t wire_read_u16(const uint8_t *pos)
{
	return be16toh(*(uint16_t *)pos);
}

/*!
 * \brief Reads 4 bytes from the wireformat data.
 *
 * \param pos Data to read the 4 bytes from.
 *
 * \return The 4 bytes read, in host byte order.
 */
inline static uint32_t wire_read_u32(const uint8_t *pos)
{
	return be32toh(*(uint32_t *)pos);
}

/*!
 * \brief Reads 6 bytes from the wireformat data.
 *
 * \param pos Data to read the 6 bytes from.
 *
 * \return The 6 bytes read, in host byte order.
 */
inline static uint64_t wire_read_u48(const uint8_t *pos)
{
	uint64_t input = 0;
	memcpy((uint8_t *)&input + 1, pos, 6);
	return be64toh(input) >> 8;
}

/*!
 * \brief Read 8 bytes from the wireformat data.
 *
 * \param pos Data to read the 8 bytes from.
 *
 * \return The 8 bytes read, in host byte order.
 */
inline static uint64_t wire_read_u64(const uint8_t *pos)
{
	return be64toh(*(uint64_t *)pos);
}

/*!
 * \brief Writes 2 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 2 bytes.
 * \param data Data to put.
 */
inline static void wire_write_u16(uint8_t *pos, uint16_t data)
{
	*(uint16_t *)pos = htobe16(data);
}

/*!
 * \brief Writes 4 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 4 bytes.
 * \param data Data to put.
 */
inline static void wire_write_u32(uint8_t *pos, uint32_t data)
{
	*(uint32_t *)pos = htobe32(data);
}

/*!
 * \brief Writes 6 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 4 bytes.
 * \param data Data to put.
 */
inline static void wire_write_u48(uint8_t *pos, uint64_t data)
{
	uint64_t swapped = htobe64(data << 8);
	memcpy(pos, (uint8_t *)&swapped + 1, 6);
}

/*!
 * \brief Writes 8 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 8 bytes.
 * \param data Data to put.
 */
inline static void wire_write_u64(uint8_t *pos, uint64_t data)
{
	*(uint64_t *)pos = htobe64(data);
}

/*! @} */
