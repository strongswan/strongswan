/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_encrypt_param_sets.h is a component of ntru-crypto.
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
 * File: ntru_crypto_ntru_encrypt_param_sets.h
 *
 * Contents: Definitions and declarations for the NTRUEncrypt parameter sets.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H
#define NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H

#include "ntru_crypto.h"

/* structures */

typedef struct _NTRU_ENCRYPT_PARAM_SET {
    NTRU_ENCRYPT_PARAM_SET_ID id;                 /* parameter-set ID */
    uint8_t const             OID[3];             /* pointer to OID */
    uint8_t                   der_id;             /* parameter-set DER id */
    uint8_t                   N_bits;             /* no. of bits in N (i.e. in
                                                     an index */
    uint16_t                  N;                  /* ring dimension */
    uint16_t                  sec_strength_len;   /* no. of octets of
                                                     security strength */
    uint16_t                  q;                  /* big modulus */
    uint8_t                   q_bits;             /* no. of bits in q (i.e. in
                                                     a coefficient */
    bool                      is_product_form;    /* if product form used */
    uint32_t                  dF_r;               /* no. of 1 or -1 coefficients
                                                     in ring elements F, r */
    uint16_t                  dg;                 /* no. - 1 of 1 coefficients
                                                     or no. of -1 coefficients
                                                     in ring element g */
    uint16_t                  m_len_max;          /* max no. of plaintext
                                                     octets */
    uint16_t                  min_msg_rep_wt;     /* min. message
                                                     representative weight */
    uint8_t                   c_bits;             /* no. bits in candidate for
                                                     deriving an index in
                                                     IGF-2 */
    uint8_t                   m_len_len;          /* no. of octets to hold
                                                     mLenOctets */
} NTRU_ENCRYPT_PARAM_SET;



/* function declarations */

/* ntru_encrypt_get_params_with_id
 *
 * Looks up a set of NTRU Encrypt parameters based on the id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id);  /*  in - parameter-set id */


/* ntru_encrypt_get_params_with_OID
 *
 * Looks up a set of NTRU Encrypt parameters based on the OID of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

extern NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_OID(
    uint8_t const *oid);            /*  in - pointer to parameter-set OID */

#endif /* NTRU_CRYPTO_NTRU_ENCRYPT_PARAM_SETS_H */

