/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_drbg.h is a component of ntru-crypto.
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
 * File:  ntru_crypto_drbg.h
 *
 * Contents: Public header file for ntru_crypto_drbg.c.
 *
 *****************************************************************************/


#ifndef NTRU_CRYPTO_DRBG_H
#define NTRU_CRYPTO_DRBG_H

#include "ntru_crypto_platform.h"
#include "ntru_crypto_error.h"

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

#if defined ( __cplusplus )
extern "C" {
#endif /* __cplusplus */


/*******************
 * DRBG parameters *
 *******************/

#if !defined(DRBG_MAX_INSTANTIATIONS)
#define DRBG_MAX_INSTANTIATIONS                 4
#endif
#define DRBG_MAX_SEC_STRENGTH_BITS              256
#define DRBG_MAX_BYTES_PER_BYTE_OF_ENTROPY      8


/************************
 * HMAC_DRBG parameters *
 ************************/

#define HMAC_DRBG_MAX_PERS_STR_BYTES            32
#define HMAC_DRBG_MAX_BYTES_PER_REQUEST         1024


/********************
 * type definitions *
 ********************/

typedef uint32_t DRBG_HANDLE;               /* drbg handle */
typedef enum {                              /* entropy-function commands */
    GET_NUM_BYTES_PER_BYTE_OF_ENTROPY = 0,
    INIT,
    GET_BYTE_OF_ENTROPY,
} ENTROPY_CMD;
typedef uint8_t (*ENTROPY_FN)(              /* get entropy function */
                    ENTROPY_CMD  cmd,       /* command */
                    uint8_t     *out);      /* address for output */


/***************
 * error codes *
 ***************/

#define DRBG_OK             0x00000000 /* no errors */
#define DRBG_OUT_OF_MEMORY  0x00000001 /* can't allocate memory */
#define DRBG_BAD_PARAMETER  0x00000002 /* null pointer */
#define DRBG_BAD_LENGTH     0x00000003 /* invalid no. of bytes */
#define DRBG_NOT_AVAILABLE  0x00000004 /* no instantiation slot available */
#define DRBG_ENTROPY_FAIL   0x00000005 /* entropy function failure */

/***************
 * error macro *
 ***************/

#define DRBG_RESULT(r)  ((uint32_t)((r) ? DRBG_ERROR_BASE + (r) : (r)))
#define DRBG_RET(r)     return DRBG_RESULT(r);


/*************************
 * function declarations *
 *************************/

/* ntru_crypto_drbg_instantiate
 *
 * This routine instantiates a drbg with the requested security strength.
 * See ANS X9.82: Part 3-2007.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if an argument pointer is NULL.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_LENGTH if the security strength requested
 *  or the personalization string is too large.
 * Returns DRBG_ERROR_BASE + DRBG_OUT_OF_MEMORY if the internal state cannot be
 *  allocated from the heap.
 */

NTRUCALL
ntru_crypto_drbg_instantiate(
    uint32_t       sec_strength_bits, /*  in - requested sec strength in bits */
    uint8_t const *pers_str,          /*  in - ptr to personalization string */
    uint32_t       pers_str_bytes,    /*  in - no. personalization str bytes */
    ENTROPY_FN     entropy_fn,        /*  in - pointer to entropy function */
    DRBG_HANDLE   *handle);           /* out - address for drbg handle */


/* ntru_crypto_drbg_uninstantiate
 *
 * This routine frees a drbg given its handle.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if handle is not valid.
 */

NTRUCALL
ntru_crypto_drbg_uninstantiate(
    DRBG_HANDLE handle);            /* in - drbg handle */


/* ntru_crypto_drbg_reseed
 *
 * This routine reseeds an instantiated drbg.
 * See ANS X9.82: Part 3-2007.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if handle is not valid.
 * Returns NTRU_CRYPTO_HMAC errors if they occur.
 */

NTRUCALL
ntru_crypto_drbg_reseed(
    DRBG_HANDLE handle);            /* in - drbg handle */


/* ntru_crypto_drbg_generate
 *
 * This routine generates pseudorandom bytes using an instantiated drbg.
 * If the maximum number of requests has been reached, reseeding will occur.
 * See ANS X9.82: Part 3-2007.
 *
 * Returns DRBG_OK if successful.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_PARAMETER if handle is not valid or if
 *  an argument pointer is NULL.
 * Returns DRBG_ERROR_BASE + DRBG_BAD_LENGTH if the security strength requested
 *  is too large or the number of bytes requested is zero or too large.
 * Returns NTRU_CRYPTO_HMAC errors if they occur.
 */

NTRUCALL
ntru_crypto_drbg_generate(
    DRBG_HANDLE handle,             /*  in - drbg handle */
    uint32_t    sec_strength_bits,  /*  in - requested sec strength in bits */
    uint32_t    num_bytes,          /*  in - number of octets to generate */
    uint8_t    *out);               /* out - address for generated octets */


#if defined ( __cplusplus )
}
#endif /* __cplusplus */


#endif /* NTRU_CRYPTO_DRBG_H */
