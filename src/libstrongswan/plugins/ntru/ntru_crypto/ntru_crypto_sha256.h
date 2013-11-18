/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_sha256.h is a component of ntru-crypto.
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
 * File: ntru_crypto_sha256.h
 *
 * Contents: Definitions and declarations for the SHA-256 implementation.
 *
 *****************************************************************************/

#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H


#include "ntru_crypto_platform.h"
#include "ntru_crypto_sha2.h"


/******************************************
 * macros needed for generic hash objects * 
 ******************************************/

#define SHA_256_CTX_LEN     sizeof(NTRU_CRYPTO_SHA2_CTX)
                                                       /* no. bytes in SHA-2
                                                          ctx */
#define SHA_256_BLK_LEN     64                         /* 64 bytes in input
                                                          block */
#define SHA_256_MD_LEN      32                         /* 32 bytes in msg
                                                          digest */
#define SHA_256_INIT_FN     &ntru_crypto_sha256_init   /* init function */
#define SHA_256_UPDATE_FN   &ntru_crypto_sha256_update /* update function */
#define SHA_256_FINAL_FN    &ntru_crypto_sha256_final  /* final function */
#define SHA_256_FINAL_ZERO_PAD_FN                                           \
                            &ntru_crypto_sha256_final_zero_pad
                                                       /* final function using
                                                          zero padding */
#define SHA_256_DIGEST_FN   &ntru_crypto_sha256_digest /* digest function */


/*************************
 * function declarations *
 *************************/

/* ntru_crypto_sha256_init
 *
 * This routine performs standard initialization of the SHA-256 state.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

extern uint32_t
ntru_crypto_sha256_init(
    NTRU_CRYPTO_SHA2_CTX *c);       /* in/out - pointer to SHA-2 context */


/* ntru_crypto_sha256_update
 *
 * This routine processes input data and updates the SHA-256 hash calculation.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha256_update(
    NTRU_CRYPTO_SHA2_CTX *c,         /* in/out - pointer to SHA-2 context */
    uint8_t const        *data,      /*     in - pointer to input data */
    uint32_t              data_len); /*     in - no. of bytes of input data */


/* ntru_crypto_sha256_final
 *
 * This routine completes the SHA-256 hash calculation and returns the
 * message digest.
 * 
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha256_final(
    NTRU_CRYPTO_SHA2_CTX *c,        /* in/out - pointer to SHA-2 context */
    uint8_t              *md);      /*    out - address for message digest */


/* ntru_crypto_sha256_final_zero_pad
 *
 * This routine completes the SHA-256 hash calculation using zero padding
 * and returns the message digest.
 * 
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha256_final_zero_pad(
    NTRU_CRYPTO_SHA2_CTX *c,        /* in/out - pointer to SHA-2 context */
    uint8_t              *md);      /*    out - address for message digest */


/* ntru_crypto_sha256_digest
 *
 * This routine computes a SHA-256 message digest.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

extern uint32_t
ntru_crypto_sha256_digest(
    uint8_t const  *data,           //  in - pointer to input data
    uint32_t        data_len,       //  in - number of bytes of input data
    uint8_t        *md);            // out - address for message digest


#endif /* CRYPTO_SHA256_H */
