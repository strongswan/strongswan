/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup byteorder_i byteorder
 * @{ @ingroup utils_i
 */

#ifndef BYTEORDER_H_
#define BYTEORDER_H_

/**
 * Architecture independent bitfield definition helpers (at least with GCC).
 *
 * Defines a bitfield with a type t and a fixed size of bitfield members, e.g.:
 * BITFIELD2(u_int8_t,
 *     low: 4,
 *     high: 4,
 * ) flags;
 * The member defined first placed at bit 0.
 */
#if BYTE_ORDER == LITTLE_ENDIAN
#define BITFIELD2(t, a, b,...)			struct { t a; t b; __VA_ARGS__}
#define BITFIELD3(t, a, b, c,...)		struct { t a; t b; t c; __VA_ARGS__}
#define BITFIELD4(t, a, b, c, d,...)	struct { t a; t b; t c; t d; __VA_ARGS__}
#define BITFIELD5(t, a, b, c, d, e,...)	struct { t a; t b; t c; t d; t e; __VA_ARGS__}
#elif BYTE_ORDER == BIG_ENDIAN
#define BITFIELD2(t, a, b,...)			struct { t b; t a; __VA_ARGS__}
#define BITFIELD3(t, a, b, c,...)		struct { t c; t b; t a; __VA_ARGS__}
#define BITFIELD4(t, a, b, c, d,...)	struct { t d; t c; t b; t a; __VA_ARGS__}
#define BITFIELD5(t, a, b, c, d, e,...)	struct { t e; t d; t c; t b; t a; __VA_ARGS__}
#endif

/**
 * Write a 16-bit host order value in network order to an unaligned address.
 *
 * @param host		host order 16-bit value
 * @param network	unaligned address to write network order value to
 */
static inline void htoun16(void *network, u_int16_t host)
{
	char *unaligned = (char*)network;

	host = htons(host);
	memcpy(unaligned, &host, sizeof(host));
}

/**
 * Write a 32-bit host order value in network order to an unaligned address.
 *
 * @param host		host order 32-bit value
 * @param network	unaligned address to write network order value to
 */
static inline void htoun32(void *network, u_int32_t host)
{
	char *unaligned = (char*)network;

	host = htonl(host);
	memcpy((char*)unaligned, &host, sizeof(host));
}

/**
 * Write a 64-bit host order value in network order to an unaligned address.
 *
 * @param host		host order 64-bit value
 * @param network	unaligned address to write network order value to
 */
static inline void htoun64(void *network, u_int64_t host)
{
	char *unaligned = (char*)network;

#ifdef be64toh
	host = htobe64(host);
	memcpy((char*)unaligned, &host, sizeof(host));
#else
	u_int32_t high_part, low_part;

	high_part = host >> 32;
	high_part = htonl(high_part);
	low_part  = host & 0xFFFFFFFFLL;
	low_part  = htonl(low_part);

	memcpy(unaligned, &high_part, sizeof(high_part));
	unaligned += sizeof(high_part);
	memcpy(unaligned, &low_part, sizeof(low_part));
#endif
}

/**
 * Read a 16-bit value in network order from an unaligned address to host order.
 *
 * @param network	unaligned address to read network order value from
 * @return			host order value
 */
static inline u_int16_t untoh16(void *network)
{
	char *unaligned = (char*)network;
	u_int16_t tmp;

	memcpy(&tmp, unaligned, sizeof(tmp));
	return ntohs(tmp);
}

/**
 * Read a 32-bit value in network order from an unaligned address to host order.
 *
 * @param network	unaligned address to read network order value from
 * @return			host order value
 */
static inline u_int32_t untoh32(void *network)
{
	char *unaligned = (char*)network;
	u_int32_t tmp;

	memcpy(&tmp, unaligned, sizeof(tmp));
	return ntohl(tmp);
}

/**
 * Read a 64-bit value in network order from an unaligned address to host order.
 *
 * @param network	unaligned address to read network order value from
 * @return			host order value
 */
static inline u_int64_t untoh64(void *network)
{
	char *unaligned = (char*)network;

#ifdef be64toh
	u_int64_t tmp;

	memcpy(&tmp, unaligned, sizeof(tmp));
	return be64toh(tmp);
#else
	u_int32_t high_part, low_part;

	memcpy(&high_part, unaligned, sizeof(high_part));
	unaligned += sizeof(high_part);
	memcpy(&low_part, unaligned, sizeof(low_part));

	high_part = ntohl(high_part);
	low_part  = ntohl(low_part);

	return (((u_int64_t)high_part) << 32) + low_part;
#endif
}

#endif /** BYTEORDER_H_ @} */
