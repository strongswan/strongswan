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
typedef enum pts_pcr_transform_t pts_pcr_transform_t;
typedef struct tcg_pts_attr_simple_comp_evid_params_t tcg_pts_attr_simple_comp_evid_params_t;

#include "tcg_attr.h"
#include "pts/pts_meas_algo.h"
#include "pts/pts_funct_comp_name.h" 
#include "pa_tnc/pa_tnc_attr.h"

/**
 * PTS Simple Component Evidence Flags
 */
enum pts_attr_simple_comp_evid_flag_t {
	/** No Validation was attempted */
	PTS_SIMPLE_COMP_EVID_FLAG_NO_VALID =	 1,
	/** Attempted validation, unable to verify */
	PTS_SIMPLE_COMP_EVID_FLAG_NO_VER =		 2,
	/** Attempted validation, verification failed */
	PTS_SIMPLE_COMP_EVID_FLAG_VER_FAIL =	 3,
	/** Attempted validation, verification passed */
	PTS_SIMPLE_COMP_EVID_FLAG_VER_PASS =	 4,
};

/**
 * PTS PCR Transformations
 */
enum pts_pcr_transform_t {
	/** No Transformation */
	PTS_PCR_TRANSFORM_NO =		0,
	/** Hash Value matched PCR size */
	PTS_PCR_TRANSFORM_MATCH =	 1,
	/** Hash value shorter than PCR size */
	PTS_PCR_TRANSFORM_SHORT =	 2,
	/** Hash value longer than PCR size */
	PTS_PCR_TRANSFORM_LONG =	 3,
};

/**
 * Parameters for Simple Component Evidence Attribute
 */
struct tcg_pts_attr_simple_comp_evid_params_t {
	bool pcr_info_included;
	pts_attr_simple_comp_evid_flag_t flags;
	u_int32_t depth;
	u_int32_t vendor_id;
	pts_qualifier_t qualifier;
	pts_funct_comp_name_t name;
	u_int32_t extended_pcr;
	pts_meas_algorithms_t hash_algorithm;
	pts_pcr_transform_t transformation;
	chunk_t measurement_time;
	chunk_t policy_uri;
	chunk_t pcr_before;
	chunk_t pcr_after;
	chunk_t measurement;
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
	 * Is Optional PCR Information fields included
	 *
	 * @return					TRUE if included, FALSE otherwise
	 */
	bool (*is_pcr_info_included)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get flags for PTS Simple Component Evidence
	 *
	 * @return					Set of flags
	 */
	pts_attr_simple_comp_evid_flag_t (*get_flags)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Sub-component Depth
	 *
	 * @return					Sub-component Depth
	 */
	u_int32_t (*get_sub_component_depth)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Specific Component Functional Name Vendor ID
	 *
	 * @return					Component Functional Name Vendor ID
	 */
	u_int32_t (*get_spec_comp_funct_name_vendor_id)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Family
	 *
	 * @return					Functional Name Family
	 */
	u_int8_t (*get_family)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Qualifier
	 *
	 * @return					Functional Name Category Qualifier
	 */
	pts_qualifier_t (*get_qualifier)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Special Component Functional Name
	 *
	 * @return					Component Functional Name
	 */
	pts_funct_comp_name_t (*get_comp_funct_name)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Measurement Type
	 *
	 * @return					Measurement Type
	 */
	u_int8_t (*get_measurement_type)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get which PCR the functional component is extended into
	 *
	 * @return					Number of PCR
	 */
	u_int32_t (*get_extended_pcr)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Hash Algorithm
	 *
	 * @return					Hash Algorithm
	 */
	pts_meas_algorithms_t (*get_hash_algorithm)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get PCR Transformation
	 *
	 * @return					Transformation type of PCR
	 */
	pts_pcr_transform_t (*get_pcr_trans)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Measurement Time
	 *
	 * @return					Measurement time
	 */
	chunk_t (*get_measurement_time)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Optional Policy URI
	 *
	 * @return					Policy URI
	 */
	chunk_t (*get_policy_uri)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Optional PCR Length
	 *
	 * @return					Length of PCR before/after values
	 */
	u_int16_t (*get_pcr_len)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Optional PCR before value
	 *
	 * @return					PCR before value
	 */
	chunk_t (*get_pcr_before_value)(tcg_pts_attr_simple_comp_evid_t *this);

	/**
	 * Get Optional PCR after value
	 *
	 * @return					PCR after value
	 */
	chunk_t (*get_pcr_after_value)(tcg_pts_attr_simple_comp_evid_t *this);
	
	/**
	 * Get Component Measurement
	 *
	 * @return					Component Measurement Hash
	 */
	chunk_t (*get_comp_measurement)(tcg_pts_attr_simple_comp_evid_t *this);
	
};

/**
 * Creates an tcg_pts_attr_simple_comp_evid_t object
 * 
 * @param params				Struct of parameters
 */
pa_tnc_attr_t* tcg_pts_attr_simple_comp_evid_create(tcg_pts_attr_simple_comp_evid_params_t params);

/**
 * Creates an tcg_pts_attr_simple_comp_evid_t object from received data
 *
 * @param value					Unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_simple_comp_evid_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_SIMPLE_COMP_EVID_H_ @}*/
