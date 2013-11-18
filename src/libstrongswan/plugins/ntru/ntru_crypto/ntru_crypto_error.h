/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_serror.h is a component of ntru-crypto.
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
 * File:  ntru_crypto_error.h
 *
 * Contents: Contains base values for crypto error codes.
 *
 *****************************************************************************/


#ifndef NTRU_CRYPTO_ERROR_H
#define NTRU_CRYPTO_ERROR_H

/* define base values for crypto error codes */

#define HASH_ERROR_BASE     ((uint32_t)0x00000100)
#define HMAC_ERROR_BASE     ((uint32_t)0x00000200)
#define SHA_ERROR_BASE      ((uint32_t)0x00000400)
#define DRBG_ERROR_BASE     ((uint32_t)0x00000a00)
#define NTRU_ERROR_BASE     ((uint32_t)0x00003000)
#define MGF1_ERROR_BASE     ((uint32_t)0x00004100)

#endif /* NTRU_CRYPTO_ERROR_H */
