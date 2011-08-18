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
 * @defgroup tcg_pts_attr_simple_comp_evid tcg_pts_attr_simple_comp_evid
 * @{ @ingroup tcg_pts_attr_simple_comp_evid
 */

#ifndef TCG_PTS_ATTR_SIMPLE_COMP_EVID_H_
#define TCG_PTS_ATTR_SIMPLE_COMP_EVID_H_

typedef struct tcg_pts_attr_simple_comp_evid_t tcg_pts_attr_simple_comp_evid_t;
typedef enum pts_attr_simple_comp_evid_flag_t pts_attr_simple_comp_evid_flag_t;
typedef enum pts_attr_simple_comp_evid_pcr_transform_t pts_attr_simple_comp_evid_pcr_transform_t;

#include "tcg_attr.h"
#include "tcg_pts_meas_algo.h"
#include "pa_tnc/pa_tnc_attr.h"

/* For Qualifier and Component Name fields, tcg_pts_qualifier_t, 
 * pts_attr_req_funct_comp_name_bin_enum_t, pts_attr_req_funct_comp_type_t */
#include "tcg_pts_attr_req_funct_comp_evid.h" 

/**
 * PTS Simple Component Evidence Flags
 */
enum pts_attr_simple_comp_evid_flag_t {
	/** PCR information fields inlcuded */
	PTS_SIMPLE_COMP_EVID_FLAG_PCR =					0,
	/** No Validation was attempted */
	PTS_SIMPLE_COMP_EVID_FLAG_NO_VALID = 				1,
	/** Attempted validation, unable to verify */
	PTS_SIMPLE_COMP_EVID_FLAG_NO_VER = 				2,
	/** Attempted validation, verification failed */
	PTS_SIMPLE_COMP_EVID_FLAG_VER_FAIL = 				3,
	/** Attempted validation, verification passed */
	PTS_SIMPLE_COMP_EVID_FLAG_VER_PASS = 				4,
};

/**
 * PTS Simple Component Evidence PCR Transformations
 */
enum pts_attr_simple_comp_evid_pcr_transform_t {
	/** No Transformation */
	PTS_SIMPLE_COMP_EVID_PCR_TRANS_NO =				0,
	/** Hash Value matched PCR size */
	PTS_SIMPLE_COMP_EVID_PCR_TRANS_MATCH = 				1,
	/** Hash value shorter than PCR size */
	PTS_SIMPLE_COMP_EVID_PCR_TRANS_SHORT = 				2,
	/** Hash value longer than PCR size */
	PTS_SIMPLE_COMP_EVID_PCR_TRANS_LONG = 				3,
};

/**
 * Class implementing the TCG PTS Simple Component Evidence attribute
 *
 */
struct tcg_pts_attr_simple_comp_evid_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;
	
	/**
	 * Get flags for PTS Simple Component Evidence
	 *
	 * @return				Set of flags
	 */
	pts_attr_simple_comp_evid_flag_t (*get_flags)(tcg_pts_attr_simple_comp_evid_t *this);

	/**
	 * Set flags for PTS Simple Component Evidence
	 *
	 * @param flags				Set of flags
	 */
	void (*set_flags)(tcg_pts_attr_simple_comp_evid_t *this, 
				pts_attr_simple_comp_evid_flag_t flags);
	
	/**
	 * Get Sub-component Depth
	 *
	 * @return				Sub-component Depth
	 */
	u_int32_t (*get_sub_component_depth)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Specific Component Functional Name Vendor ID
	 *
	 * @return				Component Functional Name Vendor ID
	 */
	u_int32_t (*get_spec_comp_funct_name_vendor_id)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Family
	 *
	 * @return				Functional Name Family
	 */
	u_int8_t (*get_family)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Qualifier
	 *
	 * @return				Functional Name Category Qualifier
	 */
	tcg_pts_qualifier_t (*get_qualifier)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Set qualifier for Component Functional Name
	 *
	 * @param qualifier			Functional Name Category Qualifier
	 */
	void (*set_qualifier)(tcg_pts_attr_simple_comp_evid_t *this,
						tcg_pts_qualifier_t qualifier);
	
	/**
	 * Get Special Component Functional Name
	 *
	 * @return				Component Functional Name
	 */
	pts_attr_req_funct_comp_name_bin_enum_t (*get_comp_funct_name)(tcg_pts_attr_simple_comp_evid_t *this);
	
	
	/**
	 * Set Component Functional Name
	 *
	 * @param name				Component Functional Name
	 */
	void (*set_comp_funct_name)(tcg_pts_attr_simple_comp_evid_t *this,
				pts_attr_req_funct_comp_name_bin_enum_t name);
	
	/**
	 * Get Measurement Type
	 *
	 * @return				Measurement Type
	 */
	u_int8_t (*get_measurement_type)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get which PCR the functional component is extended into 
	 *
	 * @return				Number of PCR
	 */
	u_int32_t (*get_extended_pcr)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Set which PCR the functional component is extended into 
	 *
	 * @param pcr_number			Number of PCR
	 */
	void (*set_extended_pcr)(tcg_pts_attr_simple_comp_evid_t *this,
						u_int32_t extended_pcr);
	
	/**
	 * Get Hash Algorithm
	 *
	 * @return				Hash Algorithm
	 */
	pts_meas_algorithms_t (*get_hash_algorithm)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Set Hash Algorithm
	 *
	 * @param hash_algorithm			Hash Algorithm
	 */
	void (*set_hash_algorithm)(tcg_pts_attr_simple_comp_evid_t *this,
						pts_meas_algorithms_t hash_algorithm);
	
	/**
	 * Get PCR Transformation 
	 *
	 * @return				Transformation type of PCR
	 */
	pts_attr_simple_comp_evid_pcr_transform_t (*get_pcr_trans)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Set PCR Transformation
	 *
	 * @param transformation		Transformation type of PCR
	 */
	void (*set_pcr_trans)(tcg_pts_attr_simple_comp_evid_t *this,
			pts_attr_simple_comp_evid_pcr_transform_t transformation);
	
	/**
	 * Get Measurement Time
	 *
	 * @return				Measurement time
	 */
	chunk_t (*get_measurement_time)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Set Measurement Time
	 *
	 * @param time		Measurement time
	 */
	void (*set_measurement_time)(tcg_pts_attr_simple_comp_evid_t *this,
						chunk_t time);
	
	/**
	 * Get Optional Policy URI
	 *
	 * @return				Policy URI
	 */
	chunk_t (*get_policy_uri)(tcg_pts_attr_simple_comp_evid_t *this);
		
	/**
	 * Set Optional Policy URI
	 *
	 * @param policy_uri			Policy URI
	 */
	void (*set_policy_uri)(tcg_pts_attr_simple_comp_evid_t *this,
						chunk_t policy_uri);
	
	/**
	 * Get Optional PCR Length
	 *
	 * @return				Length of PCR before/after values
	 */
	u_int16_t (*get_pcr_len)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Optional PCR before value
	 *
	 * @return				PCR before value
	 */
	chunk_t (*get_pcr_before_value)(tcg_pts_attr_simple_comp_evid_t *this);
		
	/**
	 * Set Optional PCR before value
	 *
	 * @param pcr_before			PCR before value
	 */
	void (*set_pcr_before_value)(tcg_pts_attr_simple_comp_evid_t *this,
						chunk_t pcr_before);
	
	/**
	 * Get Optional PCR after value
	 *
	 * @return				PCR after value
	 */
	chunk_t (*get_pcr_after_value)(tcg_pts_attr_simple_comp_evid_t *this);
		
	/**
	 * Set Optional PCR after value
	 *
	 * @param pcr_after			PCR after value
	 */
	void (*set_pcr_after_value)(tcg_pts_attr_simple_comp_evid_t *this,
						chunk_t pcr_after);
	
	/**
	 * Get Component Measurement
	 *
	 * @return				Component Measurement Hash
	 */
	chunk_t (*get_comp_measurement)(tcg_pts_attr_simple_comp_evid_t *this);
		
	/**
	 * Set Component Measurement
	 *
	 * @param measurement			Component Measurement Hash
	 */
	void (*set_comp_measurement)(tcg_pts_attr_simple_comp_evid_t *this,
						chunk_t measurement);
	
};

/**
 * Creates an tcg_pts_attr_simple_comp_evid_t object
 * 
 * @param flags				Set of flags
 * @param depth				Sub-component Depth
 * @param vendor_id			Component Functional Name Vendor ID
 * @param qualifier			Functional Name Category Qualifier
 * @param name				Component Functional Name
 * @param extended_pcr			Which PCR the functional component is extended into 
 * @param hash_algorithm		Hash Algorithm
 * @param transformation		Transformation type for PCR
 * @param measurement_time		Measurement time
 * @param policy_uri			Optional Policy URI
 * @param pcr_before			Optional PCR before value
 * @param pcr_after			Optional PCR after value
 * @param measurement			Component Measurement
 */
pa_tnc_attr_t* tcg_pts_attr_simple_comp_evid_create(pts_attr_simple_comp_evid_flag_t flags,
				       u_int32_t depth, 
				       u_int32_t vendor_id,
				       tcg_pts_qualifier_t qualifier,
				       pts_attr_req_funct_comp_name_bin_enum_t name,
				       u_int32_t extended_pcr,
				       pts_meas_algorithms_t hash_algorithm,
				       pts_attr_simple_comp_evid_pcr_transform_t transformation,
				       chunk_t measurement_time,
				       chunk_t policy_uri,
				       chunk_t pcr_before,
				       chunk_t pcr_after,
				       chunk_t measurement);

/**
 * Creates an tcg_pts_attr_simple_comp_evid_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_simple_comp_evid_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_SIMPLE_COMP_EVID_H_ @}*/
