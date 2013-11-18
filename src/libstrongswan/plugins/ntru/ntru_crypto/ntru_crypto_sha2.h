/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_crypto_sha2.h is a component of ntru-crypto.
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
 * File: ntru_crypto_sha2.h
 *
 * Contents: Definitions and declarations for the SHA-256 implementation.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_SHA2_H
#define NTRU_CRYPTO_SHA2_H


#include "ntru_crypto_platform.h"
#include "ntru_crypto_sha.h"


/*************************
 * structure definitions *
 *************************/

/* SHA-256 context structure */

typedef struct {
    uint32_t    state[8];           /* chaining state */
    uint32_t    num_bits_hashed[2]; /* number of bits hashed */
    uint8_t     unhashed[64];       /* input data not yet hashed */
    uint32_t    unhashed_len;       /* number of bytes of unhashed input data */
} NTRU_CRYPTO_SHA2_CTX;


/*************************
 * function declarations *
 *************************/

/* ntru_crypto_sha2()
 *
 * This routine provides all operations for a SHA-256 hash,
 * and the use of SHA-256 for DSA signing and key generation.
 * It may be used to initialize, update, or complete a message digest,
 * or any combination of those actions, as determined by the SHA_INIT flag,
 * the in_len parameter, and the SHA_FINISH flag, respectively.
 *
 * When in_len == 0 (no data to hash), the parameter, in, may be NULL.
 * When the SHA_FINISH flag is not set, the parameter, md, may be NULL.
 *
 * Initialization may be standard or use a specified initialization vector,
 * and is indicated by setting the SHA_INIT flag.
 * Setting init = NULL specifies standard initialization.  Otherwise, init
 * points to the array of eight alternate initialization 32-bit words.
 *
 * The hash operation can be updated with any number of input bytes, including
 * zero.
 *
 * The hash operation can be completed with normal padding or with zero
 * padding as required for parts of DSA parameter generation, and is indicated
 * by setting the SHA_FINISH flag.  Using zero padding, indicated by setting
 * the SHA_ZERO_PAD flag, never creates an extra input block because the
 * bit count is not included in the hashed data.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha2(
    NTRU_CRYPTO_HASH_ALGID  algid,  /*     in - hash algorithm ID */
    NTRU_CRYPTO_SHA2_CTX   *c,      /* in/out - pointer to SHA-2 context */
    uint32_t const         *init,   /*     in - pointer to alternate */
                                    /*          initialization - may be NULL */
    uint8_t const          *in,     /*     in - pointer to input data -
                                                may be NULL if in_len == 0 */
    uint32_t                in_len, /*     in - number of input data bytes */
    uint32_t                flags,  /*     in - INIT, FINISH, zero-pad flags */
    uint8_t                *md);    /*    out - address for message digest -
                                                may be NULL if not FINISH */


#endif /* NTRU_CRYPTO_SHA2_H */
