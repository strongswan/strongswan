/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_sha.h is a component of ntru-crypto.
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
 * File: ntru_crypto_sha.h
 *
 * Contents: Definitions and declarations common to all SHA hash algorithms.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_SHA_H
#define NTRU_CRYPTO_SHA_H


#include "ntru_crypto_error.h"
#include "ntru_crypto_hash_basics.h"


/***************
 * error codes *
 ***************/

#define SHA_OK              ((uint32_t)NTRU_CRYPTO_HASH_OK)
#define SHA_FAIL            ((uint32_t)NTRU_CRYPTO_HASH_FAIL)
#define SHA_BAD_PARAMETER   ((uint32_t)NTRU_CRYPTO_HASH_BAD_PARAMETER)
#define SHA_OVERFLOW        ((uint32_t)NTRU_CRYPTO_HASH_OVERFLOW)

#define SHA_RESULT(r)   ((uint32_t)((r) ? SHA_ERROR_BASE + (r) : (r)))
#define SHA_RET(r)      return SHA_RESULT(r);


/*********
 * flags *
 *********/

#define SHA_DATA_ONLY       HASH_DATA_ONLY
#define SHA_INIT            HASH_INIT
#define SHA_FINISH          HASH_FINISH
#define SHA_ZERO_PAD        HASH_ZERO_PAD


#endif /* NTRU_CRYPTO_SHA_H */

