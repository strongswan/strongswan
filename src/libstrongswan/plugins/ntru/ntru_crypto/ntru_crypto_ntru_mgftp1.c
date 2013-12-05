/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_mgftp1.c is a component of ntru-crypto.
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
 * File: ntru_crypto_ntru_mgftp1.c
 *
 * Contents: Routines implementing MGF-TP-1.
 *
 *****************************************************************************/


#include <stdlib.h>
#include <string.h>
#include "ntru_crypto_ntru_mgftp1.h"
#include "ntru_crypto_ntru_convert.h"

#include "ntru_mgf1.h"

/* ntru_mgftp1
 *
 * Implements a mask-generation function for trinary polynomials,
 * MGF-TP-1, generating an arbitrary number of octets based on hashing
 * a digest-length string concatenated with a 4-octet counter.  From
 * these octets, N trits are derived.
 *
 * The state (string and counter) is initialized when a seed is present.
 *
 * Returns NTRU_OK if successful.
 * Returns NTRU_MGF1_FAIL if the MGF1 mask generator function fails
 *
 */

uint32_t
ntru_mgftp1(
	hash_algorithm_t        hash_algid,       /*  in - hash alg ID for
                                                       MGF-TP-1 */
	uint8_t                 min_calls,        /*  in - minimum no. of hash
                                                       calls */
	uint16_t                seed_len,         /*  in - no. of octets in seed */
	uint8_t                *seed,             /*  in - pointer to seed */
	uint8_t                *buf,              /*  in - pointer to working
                                                       buffer */
	uint16_t                num_trits_needed, /*  in - no. of trits in mask */
	uint8_t                *mask)             /* out - address for mask trits */
{
	uint8_t   md_len;
	uint8_t  *octets;
	uint16_t  octets_available;
	ntru_mgf1_t *mgf1;

	/* generate minimum MGF1 output */
	mgf1 = ntru_mgf1_create(hash_algid, chunk_create(seed, seed_len), TRUE);
	if (!mgf1)
	{
	    return NTRU_MGF1_FAIL;
	}
	md_len = mgf1->get_hash_size(mgf1);
	octets = buf;
	octets_available = min_calls * md_len;

	DBG2(DBG_LIB, "MGF1 generates %u octets", octets_available);
	if (!mgf1->get_mask(mgf1, octets_available, octets))
	{
		mgf1->destroy(mgf1);
		return NTRU_MGF1_FAIL;
	}

	/* get trits for mask */
	while (num_trits_needed >= 5)
	{
		/* get another octet and convert it to 5 trits */
		if (octets_available == 0)
		{
			octets = buf;
			octets_available = md_len;

			DBG2(DBG_LIB, "MGF1 generates another %u octets", octets_available);
			if (!mgf1->get_mask(mgf1, octets_available, octets))
			{
				mgf1->destroy(mgf1);
				return NTRU_MGF1_FAIL;
			}
		}

		if (*octets < 243)
		{
			ntru_octet_2_trits(*octets, mask);
			mask += 5;
			num_trits_needed -= 5;
		}
		octets++;
		--octets_available;
	}

	/* get any remaining trits */
	while (num_trits_needed)
	{
		uint8_t trits[5];

		/* get another octet and convert it to remaining trits */
		if (octets_available == 0)
		{
			octets = buf;
			octets_available = md_len;

			DBG2(DBG_LIB, "MGF1 generates another %u octets", octets_available);
			if (!mgf1->get_mask(mgf1, octets_available, octets))
			{
				mgf1->destroy(mgf1);
			    return NTRU_MGF1_FAIL;
			}
		}
		if (*octets < 243)
		{
			ntru_octet_2_trits(*octets, trits);
			memcpy(mask, trits, num_trits_needed);
			num_trits_needed = 0;
		}
		else
		{
			octets++;
			--octets_available;
		}
	}
	mgf1->destroy(mgf1);

	return NTRU_OK;
}


