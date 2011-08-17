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
 * @defgroup tcg_pts_attr_simple_evid_final tcg_pts_attr_simple_evid_final
 * @{ @ingroup tcg_pts_attr_simple_evid_final
 */

#ifndef TCG_PTS_ATTR_SIMPLE_EVID_FINAL_H_
#define TCG_PTS_ATTR_SIMPLE_EVID_FINAL_H_

typedef struct tcg_pts_attr_simple_evid_final_t tcg_pts_attr_simple_evid_final_t;
typedef enum pts_simple_evid_final_flag_t pts_simple_evid_final_flag_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"
/* For Optional Composite Hash Algorithm field, pts_attr_meas_algorithms_t*/
#include "tcg_pts_attr_meas_algo_selection.h" 

/**
 * PTS Simple Evidence Final Flags
 */
enum pts_simple_evid_final_flag_t {
	/** No Optional TPM PCR Composite nor Optional TPM Quote Signature fields included */
	PTS_SIMPLE_EVID_FINAL_FLAG_NO =							0,
	/** Optional TPM PCR Composite and Optional TPM Quote Signature fields included */
	/** using TPM_QUOTE_INFO */
	PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO = 			1,
	/** Optional TPM PCR Composite and Optional TPM Quote Signature fields included */
	/** using TPM_QUOTE_INFO2, TPM_CAP_VERSION_INFO was not appended */
	PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2 = 			2,
	/** Optional TPM PCR Composite and Optional TPM Quote Signature fields included */
	/** using TPM_QUOTE_INFO2, TPM_CAP_VERSION_INFO was appended */
	PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2_CAP_VER = 	3,
	/** Optional Evidence Signature included */
	PTS_SIMPLE_EVID_FINAL_FLAG_EVID = 						4,
};

/**
 * Class implementing the TCG PTS Simple Evidence Final attribute
 *
 */
struct tcg_pts_attr_simple_evid_final_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;
	
	/**
	 * Get flags for PTS Simple Evidence Final
	 *
	 * @return				Set of flags
	 */
	pts_simple_evid_final_flag_t (*get_flags)(tcg_pts_attr_simple_evid_final_t *this);

	/**
	 * Set flags for PTS Simple Evidence Final
	 *
	 * @param flags				Set of flags
	 */
	void (*set_flags)(tcg_pts_attr_simple_evid_final_t *this, 
					  pts_simple_evid_final_flag_t flags);
	
	/**
	 * Get Optional Composite Hash Algorithm
	 *
	 * @return				Composite Hash Algorithm
	 */
	pts_meas_algorithms_t (*get_comp_hash_algorithm)(tcg_pts_attr_simple_evid_final_t *this);
	
	/**
	 * Set Optional Composite Hash Algorithm
	 *
	 * @param hash_algorithm		Composite Hash Algorithm
	 */
	void (*set_comp_hash_algorithm)(tcg_pts_attr_simple_evid_final_t *this,
									pts_meas_algorithms_t hash_algorithm);
		
	/**
	 * Get Optional TPM PCR Composite Length
	 *
	 * @return				Length of Composite PCR Length
	 */
	u_int32_t (*get_comp_pcr_len)(tcg_pts_attr_simple_evid_final_t *this);
	
	/**
	 * Get Optional TPM PCR Composite  
	 *
	 * @return				PCR Composite
	 */
	chunk_t (*get_pcr_comp)(tcg_pts_attr_simple_evid_final_t *this);
		
	/**
	 * Set Optional TPM PCR Composite 
	 *
	 * @param pcr_comp			PCR Composite
	 */
	void (*set_pcr_comp)(tcg_pts_attr_simple_evid_final_t *this,
						chunk_t pcr_comp);
	
	/**
	 * Get Optional TPM Quote Signature Length
	 *
	 * @return				TPM Quote Signature Length
	 */
	u_int32_t (*get_tpm_quote_sign_len)(tcg_pts_attr_simple_evid_final_t *this);
	
	/**
	 * Get Optional TPM Quote Signature 
	 *
	 * @return				TPM Quote Signature 
	 */
	chunk_t (*get_tpm_quote_sign)(tcg_pts_attr_simple_evid_final_t *this);
		
	/**
	 * Set Optional TPM Quote Signature  
	 *
	 * @param tpm_quote_sign		TPM Quote Signature 
	 */
	void (*set_tpm_quote_sign)(tcg_pts_attr_simple_evid_final_t *this,
						chunk_t tpm_quote_sign);
	
	/**
	 * Get Optional Evidence Signature
	 *
	 * @return				Optional Evidence Signature
	 */
	chunk_t (*get_evid_sign)(tcg_pts_attr_simple_evid_final_t *this);
		
	/**
	 * Set Optional Evidence Signature
	 *
	 * @param signature			Optional Evidence Signature
	 */
	void (*set_evid_sign)(tcg_pts_attr_simple_evid_final_t *this,
						chunk_t signature);
	
};

/**
 * Creates an tcg_pts_attr_simple_evid_final_t object
 * 
 * @param flags				Set of flags
 * @param comp_hash_algorithm		Composite Hash Algorithm
 * @param pcr_comp			Optional TPM PCR Composite
 * @param tpm_quote_sign		Optional TPM Quote Signature
 * @param evid_sign			Optional Evidence Signature
 */
pa_tnc_attr_t* tcg_pts_attr_simple_evid_final_create(pts_simple_evid_final_flag_t flags,
				       pts_meas_algorithms_t comp_hash_algorithm,
				       chunk_t pcr_comp,
				       chunk_t tpm_quote_sign,
				       chunk_t evid_sign);

/**
 * Creates an tcg_pts_attr_simple_evid_final_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_simple_evid_final_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_SIMPLE_EVID_FINAL_H_ @}*/
