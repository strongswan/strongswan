/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_encrypt.c is a component of ntru-crypto.
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
 * File: ntru_crypto_ntru_encrypt.c
 *
 * Contents: Routines implementing NTRUEncrypt encryption and decryption and
 *           key generation.
 *
 *****************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_key.h"
#include "ntru_crypto_ntru_convert.h"
#include "ntru_crypto_ntru_poly.h"

#include "ntru_param_set.h"
#include "ntru_trits.h"
#include "ntru_poly.h"

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
  * zero, or if pt_len exceeds the maximum plaintext length for the parameter set.
 * Returns NTRU_BAD_PUBLIC_KEY if the public-key blob is invalid
 *  (unknown format, corrupt, bad length).
 * Returns NTRU_BUFFER_TOO_SMALL if the ciphertext buffer is too small.
 * Returns NTRU_NO_MEMORY if memory needed cannot be allocated from the heap.
 */

uint32_t
ntru_crypto_ntru_encrypt(
    ntru_drbg_t    *drbg,            /*     in - handle of DRBG */
    uint16_t        pubkey_blob_len, /*     in - no. of octets in public key
                                                 blob */
    uint8_t const  *pubkey_blob,     /*     in - pointer to public key */
    uint16_t        pt_len,          /*     in - no. of octets in plaintext */
    uint8_t const  *pt,              /*     in - pointer to plaintext */
    uint16_t       *ct_len,          /* in/out - no. of octets in ct, addr for
                                                 no. of octets in ciphertext */
    uint8_t        *ct)              /*    out - address for ciphertext */
{
    ntru_param_set_t       *params = NULL;
    uint8_t const          *pubkey_packed = NULL;
    uint8_t                 pubkey_pack_type = 0x00;
    uint16_t                packed_ct_len;
    size_t                  scratch_buf_len;
    uint32_t                dr;
    uint32_t                dr1 = 0;
    uint32_t                dr2 = 0;
    uint32_t                dr3 = 0;
    uint16_t                ring_mult_tmp_len;
    int16_t                 m1;
    uint16_t               *scratch_buf = NULL;
    uint16_t               *ringel_buf = NULL;
    uint8_t                *b_buf = NULL;
    uint8_t                *tmp_buf = NULL;
    bool                    msg_rep_good = FALSE;
    hash_algorithm_t        hash_algid;
    uint16_t                mprime_len = 0;
    uint16_t                mod_q_mask;
    uint32_t                result = NTRU_OK;
	ntru_trits_t           *mask;
	uint8_t                *mask_trits;
	chunk_t                 seed;
	ntru_poly_t				*r_poly;

    /* check for bad parameters */

	if (!pubkey_blob || !pt || !ct_len)
	{
		return NTRU_BAD_PARAMETER;
	}
	if ((pubkey_blob_len == 0) || (pt_len == 0))
	{
		return NTRU_BAD_LENGTH;
	}

    /* get a pointer to the parameter-set parameters, the packing type for
     * the public key, and a pointer to the packed public key
     */

    if (!ntru_crypto_ntru_encrypt_key_parse(TRUE /* pubkey */, pubkey_blob_len,
                                            pubkey_blob, &pubkey_pack_type,
                                            NULL, &params, &pubkey_packed,
                                            NULL))
	{
		return NTRU_BAD_PUBLIC_KEY;
	}

    /* return the ciphertext size if requested */

    packed_ct_len = (params->N * params->q_bits + 7) >> 3;
    if (!ct)
	{
        *ct_len = packed_ct_len;
		return NTRU_OK;
    }

    /* check the ciphertext buffer size */

    if (*ct_len < packed_ct_len)
	{
		return NTRU_BUFFER_TOO_SMALL;
    }

    /* check the plaintext length */

    if (pt_len > params->m_len_max)
	{
		return NTRU_BAD_LENGTH;
    }

    /* allocate memory for all operations */

    if (params->is_product_form)
	{
        ring_mult_tmp_len = params->N << 1; /* 2N 16-bit word buffer */
        dr1 =  params->dF_r & 0xff;
        dr2 = (params->dF_r >>  8) & 0xff;
        dr3 = (params->dF_r >> 16) & 0xff;
        dr = dr1 + dr2 + dr3;
    }
	else
	{
        ring_mult_tmp_len = params->N;      /* N 16-bit word buffer */
        dr = params->dF_r;
    }
    scratch_buf_len = (ring_mult_tmp_len << 1) +
                                            /* X-byte temp buf for ring mult and
                                                other intermediate results */
                      (params->N << 1) +    /* 2N-byte buffer for ring elements
                                                and overflow from temp buffer */
                      (dr << 2) +           /* buffer for r indices */
                      params->sec_strength_len;
                                            /* buffer for b */
    scratch_buf = malloc(scratch_buf_len);
    if (!scratch_buf)
	{
		return NTRU_OUT_OF_MEMORY;
    }
    ringel_buf = scratch_buf + ring_mult_tmp_len;
    b_buf = (uint8_t *)(ringel_buf + params->N);
    tmp_buf = (uint8_t *)scratch_buf;

	/* set hash algorithm based on security strength */
	 hash_algid = (params->sec_strength_len <= 20) ? HASH_SHA1 : HASH_SHA256;

    /* set constants */
	mod_q_mask = params->q - 1;

    /* loop until a message representative with proper weight is achieved */

    do {
        uint8_t *ptr = tmp_buf;

        /* get b */
        if (drbg->generate(drbg, params->sec_strength_len * BITS_PER_BYTE,
                                 params->sec_strength_len, b_buf))
		{
			result = NTRU_OK;
		}
		else
		{
			result = NTRU_FAIL;
		}

		if (result == NTRU_OK)
		{

            /* form sData (OID || m || b || hTrunc) */
            memcpy(ptr, params->oid, 3);
            ptr += 3;
            memcpy(ptr, pt, pt_len);
            ptr += pt_len;
            memcpy(ptr, b_buf, params->sec_strength_len);
            ptr += params->sec_strength_len;
            memcpy(ptr, pubkey_packed, params->sec_strength_len);
            ptr += params->sec_strength_len;

			DBG2(DBG_LIB, "generate polynomial r");

			seed = chunk_create(tmp_buf, ptr - tmp_buf);
			r_poly = ntru_poly_create_from_seed(hash_algid, seed, params->c_bits,
												params->N, params->q,
												params->dF_r, params->dF_r,
												params->is_product_form);
			if (!r_poly)
			{
			   result = NTRU_MGF1_FAIL;
			}
        }

		if (result == NTRU_OK)
		{
			uint16_t pubkey_packed_len;

			/* unpack the public key */
			assert(pubkey_pack_type == NTRU_KEY_PACKED_COEFFICIENTS);
			pubkey_packed_len = (params->N * params->q_bits + 7) >> 3;
			ntru_octets_2_elements(pubkey_packed_len, pubkey_packed,
								   params->q_bits, ringel_buf);

			/* form R = h * r */
			r_poly->ring_mult(r_poly, ringel_buf, ringel_buf);
			r_poly->destroy(r_poly);

			/* form R mod 4 */
			ntru_coeffs_mod4_2_octets(params->N, ringel_buf, tmp_buf);

			/* form mask */
			seed = chunk_create(tmp_buf, (params->N + 3)/4);
			mask = ntru_trits_create(params->N, hash_algid, seed);
			if (!mask)
			{
				result = NTRU_MGF1_FAIL;
			}
		}

		if (result == NTRU_OK)
		{
            uint8_t  *Mtrin_buf = tmp_buf + params->N;
            uint8_t  *M_buf = Mtrin_buf + params->N -
                              (params->sec_strength_len + params->m_len_len +
                               params->m_len_max + 2);
            uint16_t  i;

            /* form the padded message M */
            ptr = M_buf;
            memcpy(ptr, b_buf, params->sec_strength_len);
            ptr += params->sec_strength_len;
            if (params->m_len_len == 2)
                *ptr++ = (uint8_t)((pt_len >> 8) & 0xff);
            *ptr++ = (uint8_t)(pt_len & 0xff);
            memcpy(ptr, pt, pt_len);
            ptr += pt_len;

            /* add an extra zero byte in case without it the bit string
             * is not a multiple of 3 bits and therefore might not be
             * able to produce enough trits
             */

            memset(ptr, 0, params->m_len_max - pt_len + 2);

            /* convert M to trits (Mbin to Mtrin) */
            mprime_len = params->N;
			if (params->is_product_form)
			{
                --mprime_len;
			}

            ntru_bits_2_trits(M_buf, mprime_len, Mtrin_buf);
			mask_trits = mask->get_trits(mask);

			/* form the msg representative m' by adding Mtrin to mask, mod p */
			if (params->is_product_form)
			{
				m1 = 0;
				for (i = 0; i < mprime_len; i++)
				{
					tmp_buf[i] = mask_trits[i] + Mtrin_buf[i];
					if (tmp_buf[i] >= 3)
					{
						tmp_buf[i] -= 3;
					}
					if (tmp_buf[i] == 1)
					{
						++m1;
					}
					else if (tmp_buf[i] == 2)
					{
						--m1;
					}
				}
			}
			else
			{
				for (i = 0; i < mprime_len; i++)
				{
					tmp_buf[i] = mask_trits[i] + Mtrin_buf[i];
					if (tmp_buf[i] >= 3)
					{
						tmp_buf[i] -= 3;
					}
				}
			}
			mask->destroy(mask);

            /* check that message representative meets minimum weight
             * requirements
             */

            if (params->is_product_form)
                msg_rep_good = m1 < 0 ? (bool)(-m1 <= params->min_msg_rep_wt) : 
                                        (bool)( m1 <= params->min_msg_rep_wt);
            else
                msg_rep_good = ntru_poly_check_min_weight(mprime_len, tmp_buf,
                                                       params->min_msg_rep_wt);
        }
    } while ((result == NTRU_OK) && !msg_rep_good);

	if (result == NTRU_OK)
	{
        uint16_t i;

        /* form ciphertext e by adding m' to R mod q */

        for (i = 0; i < mprime_len; i++) {
            if (tmp_buf[i] == 1)
                ringel_buf[i] = (ringel_buf[i] + 1) & mod_q_mask;
            else if (tmp_buf[i] == 2)
                ringel_buf[i] = (ringel_buf[i] - 1) & mod_q_mask;
        }
        if (params->is_product_form)
            ringel_buf[i] = (ringel_buf[i] - m1) & mod_q_mask;

        /* pack ciphertext */
        ntru_elements_2_octets(params->N, ringel_buf, params->q_bits, ct);
        *ct_len = packed_ct_len;
    }

    /* cleanup */
    memset(scratch_buf, 0, scratch_buf_len);
    free(scratch_buf);
    
	return result;
}
