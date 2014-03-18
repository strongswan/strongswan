/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_cencrypt_key.h is a component of ntru-crypto.
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


#ifndef NTRU_CRYPTO_NTRU_ENCRYPT_KEY_H
#define NTRU_CRYPTO_NTRU_ENCRYPT_KEY_H

#include "ntru_crypto_ntru_convert.h"

#include "ntru_param_set.h"

/* function declarations */


/* ntru_crypto_ntru_encrypt_key_parse
 *
 * Parses an NTRUEncrypt key blob.
 * If the blob is not corrupt, returns packing types for public and private
 * keys, a pointer to the parameter set, a pointer to the public key, and
 * a pointer to the private key if it exists.
 *
 * Returns TRUE if successful.
 * Returns FALSE if the blob is invalid.
 */

extern bool
ntru_crypto_ntru_encrypt_key_parse(
    bool                     pubkey_parse,      /*  in - if parsing pubkey
                                                         blob */
    uint16_t                 key_blob_len,      /*  in - no. octets in key
                                                         blob */
    uint8_t const           *key_blob,          /*  in - pointer to key blob */
    uint8_t                 *pubkey_pack_type,  /* out - addr for pubkey
                                                         packing type */
    uint8_t                 *privkey_pack_type, /* out - addr for privkey
                                                         packing type */
    ntru_param_set_t       **params,            /* out - addr for ptr to
                                                         parameter set */
    uint8_t const          **pubkey,            /* out - addr for ptr to
                                                         packed pubkey */
    uint8_t const          **privkey);          /* out - addr for ptr to
                                                         packed privkey */

#endif /* NTRU_CRYPTO_NTRU_ENCRYPT_KEY_H */
