/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_sha256.c is a component of ntru-crypto.
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
 * File: ntru_crypto_sha256.c
 *
 * Contents: Routines implementing the SHA-256 hash calculations.
 *
 *****************************************************************************/


#include <stdlib.h>
#include "ntru_crypto_sha256.h"


/* ntru_crypto_sha256_init
 *
 * This routine performs standard initialization of the SHA-256 state.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 */

uint32_t
ntru_crypto_sha256_init(
    NTRU_CRYPTO_SHA2_CTX *c)        /* in/out - pointer to SHA-2 context */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
                            SHA_INIT, NULL);
}


/* ntru_crypto_sha256_update
 *
 * This routine processes input data and updates the SHA-256 hash calculation.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_update(
    NTRU_CRYPTO_SHA2_CTX *c,         /* in/out - pointer to SHA-2 context */
    uint8_t const        *data,      /*     in - pointer to input data */
    uint32_t              data_len)  /*     in - no. of bytes of input data */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, data,
                            data_len, SHA_DATA_ONLY, NULL);
}


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

uint32_t
ntru_crypto_sha256_final(
    NTRU_CRYPTO_SHA2_CTX *c,        /* in/out - pointer to SHA-2 context */
    uint8_t              *md)       /*    out - address for message digest */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
                            SHA_FINISH, md);
}


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

uint32_t
ntru_crypto_sha256_final_zero_pad(
    NTRU_CRYPTO_SHA2_CTX *c,        /* in/out - pointer to SHA-2 context */
    uint8_t              *md)       /*    out - address for message digest */
{
    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, c, NULL, NULL, 0,
                            SHA_FINISH | SHA_ZERO_PAD, md);
}


/* ntru_crypto_sha256_digest
 *
 * This routine computes a SHA-256 message digest.
 *
 * Returns SHA_OK on success.
 * Returns SHA_FAIL with corrupted context.
 * Returns SHA_BAD_PARAMETER if inappropriate NULL pointers are passed.
 * Returns SHA_OVERFLOW if more than 2^64 - 1 bytes are hashed.
 */

uint32_t
ntru_crypto_sha256_digest(
    uint8_t const  *data,           //  in - pointer to input data
    uint32_t        data_len,       //  in - number of bytes of input data
    uint8_t        *md)             // out - address for message digest
{
    NTRU_CRYPTO_SHA2_CTX c;

    return ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, &c, NULL, data,
                            data_len, SHA_INIT | SHA_FINISH, md);
}

