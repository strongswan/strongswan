/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup tcg_pts_attr_dh_nonce_params_resp tcg_pts_attr_dh_nonce_params_resp
 * @{ @ingroup tcg_pts_attr_dh_nonce_params_resp
 */

#ifndef TCG_PTS_ATTR_DH_NONCE_PARAMS_RESP_H_
#define TCG_PTS_ATTR_DH_NONCE_PARAMS_RESP_H_

typedef struct tcg_pts_attr_dh_nonce_params_resp_t tcg_pts_attr_dh_nonce_params_resp_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"
#include "tcg_pts_attr_dh_nonce_params_req.h"
#include "pts/pts_meas_algo.h"

/**
 * Class implementing the TCG PTS DH Nonce Parameters Response Attribute
 */
struct tcg_pts_attr_dh_nonce_params_resp_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;

	/**
	 * Get nonce length
	 *
	 * @return				Length of nonce
	 */
	u_int8_t (*get_nonce_len)(tcg_pts_attr_dh_nonce_params_resp_t *this);

	/**
	 * Get selected Diffie Hellman Group
	 *
	 * @return				Selected Diffie Hellman Group
	 */
	pts_dh_group_t (*get_dh_group)(tcg_pts_attr_dh_nonce_params_resp_t *this);

	/**
	 * Get supported hash algorithms
	 *
	 * @return				Hash algorithm set
	 */
	pts_meas_algorithms_t (*get_hash_algo_set)(tcg_pts_attr_dh_nonce_params_resp_t *this);

	/**
	 * Get DH Responder Nonce
	 *
	 * @return				DH Responder Nonce
	 */
	chunk_t (*get_responder_nonce)(tcg_pts_attr_dh_nonce_params_resp_t *this);

	/**
	 * Get DH Responder Public Value
	 *
	 * @return				DH Responder Public Value
	 */
	chunk_t (*get_responder_pub_val)(tcg_pts_attr_dh_nonce_params_resp_t *this);
	
};

/**
 * Creates an tcg_pts_attr_dh_nonce_params_resp_t object
 *
 * @param nonce_len					Length of nonce
 * @param dh_group					Selected DH group
 * @param hash_algo_set				Set of supported hash algorithms
 * @param responder_nonce			DH Responder Nonce
 * @param responder_pub_val			DH Responder Public value
 */
pa_tnc_attr_t* tcg_pts_attr_dh_nonce_params_resp_create(u_int8_t nonce_len,
												pts_dh_group_t dh_group,
												pts_meas_algorithms_t hash_algo_set,
   												chunk_t responder_nonce,
												chunk_t responder_pub_val);

/**
 * Creates an tcg_pts_attr_dh_nonce_params_resp_t object from received data
 *
 * @param value						unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_dh_nonce_params_resp_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_DH_NONCE_PARAMS_RESP_H_ @}*/
