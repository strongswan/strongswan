/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_msbyte_uint32.h is a component of ntru-crypto.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/
 
/******************************************************************************
 *
 * File: ntru_crypto_msbyte_uint32.h
 *
 * Contents: Definitions and declarations for converting between a most-
 *           significant-first byte stream and a uint32_t array.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_MSBYTE_UINT32_H
#define NTRU_CRYPTO_MSBYTE_UINT32_H


#include "ntru_crypto_platform.h"


/* ntru_crypto_msbyte_2_uint32()
 *
 * This routine converts an array of bytes in network byte order to an array
 * of uint32_t, placing the first byte in the most significant byte of the
 * first uint32_t word.
 *
 * The number of bytes in the input stream MUST be at least 4 times the
 * number of words expected in the output array.
 */

extern void
ntru_crypto_msbyte_2_uint32(
    uint32_t       *words,      // out - pointer to the output uint32_t array
    uint8_t const  *bytes,      //  in - pointer to the input byte array
    uint32_t        n);         //  in - number of words in the output array


/* ntru_crypto_uint32_2_msbyte()
 *
 * This routine converts an array of uint32_t to an array of bytes in
 * network byte order, placing the most significant byte of the first uint32_t
 * word as the first byte of the output array.
 *
 * The number of bytes in the output stream will be 4 times the number of words
 * specified in the input array.
 */

extern void
ntru_crypto_uint32_2_msbyte(
    uint8_t        *bytes,      // out - pointer to the output byte array
    uint32_t const *words,      //  in - pointer to the input uint32_t array
    uint32_t        n);         //  in - number of words in the input array


#endif /* NTRU_CRYPTO_MSBYTE_UINT32_H */
