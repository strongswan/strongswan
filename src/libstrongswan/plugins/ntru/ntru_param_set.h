/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2009-2013  Security Innovation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup ntru_param_set ntru_param_set
 * @{ @ingroup ntru_p
 */

#ifndef NTRU_PARAM_SET_H_
#define NTRU_PARAM_SET_H_

typedef enum ntru_param_set_id_t ntru_param_set_id_t;
typedef struct ntru_param_set_t ntru_param_set_t;

#include <library.h>

/**
 * NTRU encryption parameter set ID list
 */
enum ntru_param_set_id_t {
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
};

/**
 * NTRU encryption parameter set definitions
 */
struct ntru_param_set_t {
	ntru_param_set_id_t id;    /* NTRU parameter set ID */
	uint8_t  oid[3];           /* pointer to OID */
	uint8_t  der_id;           /* parameter-set DER id */
	uint8_t  N_bits;           /* no. of bits in N (i.e. in an index */
	uint16_t N;                /* ring dimension */
	uint16_t sec_strength_len; /* no. of octets of security strength */
	uint16_t q;                /* big modulus */
	uint8_t  q_bits;           /* no. of bits in q (i.e. in a coefficient */
	bool     is_product_form;  /* if product form used */
	uint32_t dF_r;             /* no. of +1 or -1 coefficients in ring elements
                                  F, r */
	uint16_t dg;               /* no. - 1 of +1 coefficients or
                                  no.     of -1 coefficients in ring element g */
	uint16_t m_len_max;        /* max no. of plaintext octets */
	uint16_t min_msg_rep_wt;   /* min. message representative weight */
	uint8_t  c_bits;           /* no. bits in candidate for deriving an index */
	uint8_t  m_len_len;        /* no. of octets to hold mLenOctets */
};

/**
 * Get NTRU encryption parameter set by NTRU parameter set ID
 *
 * @param id	NTRU parameter set ID
 * @return		NTRU parameter set
*/
ntru_param_set_t* ntru_param_set_get_by_id(ntru_param_set_id_t id);

/**
 * Get NTRU encryption parameter set by NTRU parameter set OID
 *
 * @param oid	NTRU parameter set OID
 * @return		NTRU parameter set
*/
ntru_param_set_t* ntru_param_set_get_by_oid(uint8_t const *oid);

#endif /** NTRU_PARAM_SET_H_ @}*/

