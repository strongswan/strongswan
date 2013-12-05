/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto.h is a component of ntru-crypto.
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
 * File: ntru_crypto.h
 *
 * Contents: Public header file for NTRUEncrypt.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_H
#define NTRU_CRYPTO_H

#include <library.h>

#include "ntru_drbg.h"

#if !defined( NTRUCALL )
  #if !defined(WIN32) || defined (NTRUCRYPTO_STATIC)
    // Linux, or a Win32 static library
    #define NTRUCALL extern uint32_t
  #elif defined (NTRUCRYPTO_EXPORTS)
    // Win32 DLL build
    #define NTRUCALL extern __declspec(dllexport) uint32_t
  #else
    // Win32 DLL import
    #define NTRUCALL extern __declspec(dllimport) uint32_t
  #endif
#endif /* NTRUCALL */

/* parameter set ID list */

typedef enum _NTRU_ENCRYPT_PARAM_SET_ID {
    NTRU_EES401EP1,
    NTRU_EES449EP1,
    NTRU_EES677EP1,
    NTRU_EES1087EP2,
    NTRU_EES541EP1,
    NTRU_EES613EP1,
    NTRU_EES887EP1,
    NTRU_EES1171EP1,
    NTRU_EES659EP1,
    NTRU_EES761EP1,
    NTRU_EES1087EP1,
    NTRU_EES1499EP1,
    NTRU_EES401EP2,
    NTRU_EES439EP1,
    NTRU_EES593EP1,
    NTRU_EES743EP1,
} NTRU_ENCRYPT_PARAM_SET_ID;


/* error codes */

#define NTRU_OK                     0
#define NTRU_FAIL                   1
#define NTRU_BAD_PARAMETER          2
#define NTRU_BAD_LENGTH             3
#define NTRU_BUFFER_TOO_SMALL       4
#define NTRU_INVALID_PARAMETER_SET  5
#define NTRU_BAD_PUBLIC_KEY         6
#define NTRU_BAD_PRIVATE_KEY        7
#define NTRU_OUT_OF_MEMORY          8
#define NTRU_BAD_ENCODING           9
#define NTRU_OID_NOT_RECOGNIZED    10
#define NTRU_DRBG_FAIL             11
#define NTRU_MGF1_FAIL             12

/* function declarations */

/* ntru_crypto_ntru_encrypt
 *
 * Implements NTRU encryption (SVES) for the parameter set specified in
 * the public key blob.
 *
 * Before invoking this function, a DRBG must be instantiated using
 * ntru_crypto_drbg_instantiate() to obtain a DRBG handle, and in that
 * instantiation the requested security strength must be at least as large
 * as the security strength of the NTRU parameter set being used.
 * Failure to instantiate the DRBG with the proper security strength will
 * result in this function returning DRBG_ERROR_BASE + DRBG_BAD_LENGTH.
 *
 * The required minimum size of the output ciphertext buffer (ct) may be
 * queried by invoking this function with ct = NULL.  In this case, no
 * encryption is performed, NTRU_OK is returned, and the required minimum
 * size for ct is returned in ct_len.
 *
 * When ct != NULL, at invocation *ct_len must be the size of the ct buffer.
 * Upon return it is the actual size of the ciphertext.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_DRBG_FAIL if the DRBG handle is invalid.
 * Returns NTRU_BAD_PARAMETER if an argument pointer (other than ct) is NULL.
 * Returns NTRU_BAD_LENGTH if a length argument (pubkey_blob_len or pt_len) is
 *  zero, or if pt_len exceeds the maximum plaintext length for the parameter set.
 * Returns NTRU_BAD_PUBLIC_KEY if the public-key blob is invalid
 *  (unknown format, corrupt, bad length).
 * Returns NTRU_BUFFER_TOO_SMALL if the ciphertext buffer is too small.
 * Returns NTRU_NO_MEMORY if memory needed cannot be allocated from the heap.
 */

NTRUCALL
ntru_crypto_ntru_encrypt(
    ntru_drbg_t     *drbg      ,     /*     in - handle for DRBG */
    uint16_t        pubkey_blob_len, /*     in - no. of octets in public key
                                                 blob */
    uint8_t const  *pubkey_blob,     /*     in - pointer to public key */
    uint16_t        pt_len,          /*     in - no. of octets in plaintext */
    uint8_t const  *pt,              /*     in - pointer to plaintext */
    uint16_t       *ct_len,          /* in/out - no. of octets in ct, addr for
                                                 no. of octets in ciphertext */
    uint8_t        *ct);             /*    out - address for ciphertext */


/* ntru_crypto_ntru_decrypt
 *
 * Implements NTRU decryption (SVES) for the parameter set specified in
 * the private key blob.
 *
 * The maximum size of the output plaintext may be queried by invoking
 * this function with pt = NULL.  In this case, no decryption is performed,
 * NTRU_OK is returned, and the maximum size the plaintext could be is
 * returned in pt_len.
 * Note that until the decryption is performed successfully, the actual size
 * of the resulting plaintext cannot be known.
 *
 * When pt != NULL, at invocation *pt_len must be the size of the pt buffer.
 * Upon return it is the actual size of the plaintext.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_BAD_PARAMETER if an argument pointer (other than pt) is NULL.
 * Returns NTRU_BAD_LENGTH if a length argument (privkey_blob) is zero, or if
 *  ct_len is invalid for the parameter set.
 * Returns NTRU_BAD_PRIVATE_KEY if the private-key blob is invalid
 *  (unknown format, corrupt, bad length).
 * Returns NTRU_BUFFER_TOO_SMALL if the plaintext buffer is too small.
 * Returns NTRU_NO_MEMORY if memory needed cannot be allocated from the heap.
 * Returns NTRU_FAIL if a decryption error occurs.
 */

NTRUCALL
ntru_crypto_ntru_decrypt(
    uint16_t       privkey_blob_len, /*     in - no. of octets in private key
                                                 blob */
    uint8_t const *privkey_blob,     /*     in - pointer to private key */
    uint16_t       ct_len,           /*     in - no. of octets in ciphertext */
    uint8_t const *ct,               /*     in - pointer to ciphertext */
    uint16_t      *pt_len,           /* in/out - no. of octets in pt, addr for
                                                 no. of octets in plaintext */
    uint8_t       *pt);              /*    out - address for plaintext */


/* ntru_crypto_ntru_encrypt_keygen
 *
 * Implements key generation for NTRUEncrypt for the parameter set specified.
 *
 * Before invoking this function, a DRBG must be instantiated using
 * ntru_crypto_drbg_instantiate() to obtain a DRBG handle, and in that
 * instantiation the requested security strength must be at least as large
 * as the security strength of the NTRU parameter set being used.
 * Failure to instantiate the DRBG with the proper security strength will
 * result in this function returning NTRU_DRBG_FAIL.
 *
 * The required minimum size of the output public-key buffer (pubkey_blob)
 * may be queried by invoking this function with pubkey_blob = NULL.
 * In this case, no key generation is performed, NTRU_OK is returned, and
 * the required minimum size for pubkey_blob is returned in pubkey_blob_len.
 *
 * The required minimum size of the output private-key buffer (privkey_blob)
 * may be queried by invoking this function with privkey_blob = NULL.
 * In this case, no key generation is performed, NTRU_OK is returned, and
 * the required minimum size for privkey_blob is returned in privkey_blob_len.
 *
 * The required minimum sizes of both pubkey_blob and privkey_blob may be
 * queried as described above, in a single invocation of this function.
 *
 * When pubkey_blob != NULL and privkey_blob != NULL, at invocation
 * *pubkey_blob_len must be the size of the pubkey_blob buffer and
 * *privkey_blob_len must be the size of the privkey_blob buffer.
 * Upon return, *pubkey_blob_len is the actual size of the public-key blob
 * and *privkey_blob_len is the actual size of the private-key blob.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_BAD_PARAMETER if an argument pointer (other than pubkey_blob
 * or privkey_blob) is NULL.
 * Returns NTRU_INVALID_PARAMETER_SET if the parameter-set ID is invalid.
 * Returns NTRU_BAD_LENGTH if a length argument is invalid.
 * Returns NTRU_BUFFER_TOO_SMALL if either the pubkey_blob buffer or the
 *  privkey_blob buffer is too small.
 * Returns NTRU_NO_MEMORY if memory needed cannot be allocated from the heap.
 * Returns NTRU_FAIL if the polynomial generated for f is not invertible in
 *  (Z/qZ)[X]/(X^N - 1), which is extremely unlikely.
 *  Should this occur, this function should simply be invoked again.
 */

NTRUCALL
ntru_crypto_ntru_encrypt_keygen(
    ntru_drbg_t               *drbg,             /*     in - handle of DRBG */
    NTRU_ENCRYPT_PARAM_SET_ID  param_set_id,     /*     in - parameter set ID */
    uint16_t                  *pubkey_blob_len,  /* in/out - no. of octets in
                                                             pubkey_blob, addr
                                                             for no. of octets
                                                             in pubkey_blob */
    uint8_t                   *pubkey_blob,      /*    out - address for
                                                             public key blob */
    uint16_t                  *privkey_blob_len, /* in/out - no. of octets in
                                                             privkey_blob, addr
                                                             for no. of octets
                                                             in privkey_blob */
    uint8_t                   *privkey_blob);    /*    out - address for
                                                             private key blob */
#endif /* NTRU_CRYPTO_H */
