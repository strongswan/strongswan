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

#include "ntru_param_set.h"
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

#endif /* NTRU_CRYPTO_H */
