/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_mbyte_uint32.c is a component of ntru-crypto.
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
 * File: ntru_crypto_msbyte_uint32.c
 *
 * Contents: Routines to convert between an array of bytes in network byte
 *           order (most-significant byte first) and an array of uint32 words.
 *
 *****************************************************************************/


#include <stdlib.h>
#include "ntru_crypto_msbyte_uint32.h"


/* ntru_crypto_msbyte_2_uint32()
 *
 * This routine converts an array of bytes in network byte order to an array
 * of uint32_t, placing the first byte in the most significant byte of the
 * first uint32_t word.
 *
 * The number of bytes in the input stream MUST be at least 4 times the
 * number of words expected in the output array.
 */

void
ntru_crypto_msbyte_2_uint32(
    uint32_t       *words,      // out - pointer to the output uint32_t array
    uint8_t const  *bytes,      //  in - pointer to the input byte array
    uint32_t        n)          //  in - number of words in the output array
{
    uint32_t    i;

    for (i = 0; i < n; i++) {
        words[i]  = ((uint32_t) (*bytes++)) << 24;
        words[i] |= ((uint32_t) (*bytes++)) << 16;
        words[i] |= ((uint32_t) (*bytes++)) <<  8;
        words[i] |=  (uint32_t) (*bytes++);
    }
}


/* ntru_crypto_uint32_2_msbyte()
 *
 * This routine converts an array of uint32_t to an array of bytes in
 * network byte order, placing the most significant byte of the first uint32_t
 * word as the first byte of the output array.
 *
 * The number of bytes in the output stream will be 4 times the number of words
 * specified in the input array.
 */

void
ntru_crypto_uint32_2_msbyte(
    uint8_t        *bytes,      // out - pointer to the output byte array
    uint32_t const *words,      //  in - pointer to the input uint32_t array
    uint32_t        n)          //  in - number of words in the input array
{
    uint32_t i;

    for (i = 0; i < n; i++) {
        *bytes++ = (uint8_t) (words[i] >> 24);
        *bytes++ = (uint8_t) (words[i] >> 16);
        *bytes++ = (uint8_t) (words[i] >>  8);
        *bytes++ = (uint8_t) (words[i]      );
    }
}


