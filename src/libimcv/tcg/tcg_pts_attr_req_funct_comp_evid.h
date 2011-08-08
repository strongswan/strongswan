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
 * @defgroup tcg_pts_attr_req_funct_comp_evid tcg_pts_attr_req_funct_comp_evid
 * @{ @ingroup tcg_pts_attr_req_funct_comp_evid
 */

#ifndef TCG_PTS_ATTR_REQ_FUNCT_COMP_EVID_H_
#define TCG_PTS_ATTR_REQ_FUNCT_COMP_EVID_H_

typedef struct tcg_pts_attr_req_funct_comp_evid_t tcg_pts_attr_req_funct_comp_evid_t;
typedef enum pts_attr_req_funct_comp_evid_qualifier_t pts_attr_req_funct_comp_evid_qualifier_t;
typedef enum pts_attr_req_funct_comp_name_bin_enum_t pts_attr_req_funct_comp_name_bin_enum_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"

/**
 * PTS Request Functional Component Evidence Flags
 */
enum pts_attr_req_funct_comp_evid_flag_t {
	/** Transitive Trust Chain flag */
	PTS_REQ_FUNC_COMP_TTC =					(1<<0),
	/** Verify Component flag */
	PTS_REQ_FUNC_COMP_VER = 				(1<<1),
	/** Current Evidence flag */
	PTS_REQ_FUNC_COMP_CURR = 				(1<<2),
	/** PCR Information flag */
	PTS_REQ_FUNC_COMP_PCR = 				(1<<3),
};

/**
 * PTS Request Functional Component Evidence Qualifiers
 */
enum pts_attr_req_funct_comp_evid_qualifier_t {
	/** Transitive Trust Chain flag */
	PTS_REQ_FUNC_COMP_QUAL_UNKNOWN =			(1<<0),
	/** Verify Component flag */
	PTS_REQ_FUNC_COMP_VER = 				(1<<1),
	/** Current Evidence flag */
	PTS_REQ_FUNC_COMP_CURR = 				(1<<2),
	/** PCR Information flag */
	PTS_REQ_FUNC_COMP_PCR = 				(1<<3),
};

/**
 * PTS Component Functional Name Binary Enumeration
 */
enum pts_attr_req_funct_comp_name_bin_enum_t {
	/** Transitive Trust Chain flag */
	PTS_REQ_FUNC_COMP_TTC =					(1<<0),
	/** Verify Component flag */
	PTS_REQ_FUNC_COMP_VER = 				(1<<1),
	/** Current Evidence flag */
	PTS_REQ_FUNC_COMP_CURR = 				(1<<2),
	/** PCR Information flag */
	PTS_REQ_FUNC_COMP_PCR = 				(1<<3),
};

/**
 * Class implementing the TCG PTS Request Functional Component Evidence attribute
 *
 */
struct tcg_pts_attr_req_funct_comp_evid_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;
	
	/**
	 * Get flags for PTS Request Functional Component Evidence
	 *
	 * @return				Set of flags
	 */
	pts_attr_req_funct_comp_evid_flag_t (*get_flags)(tcg_pts_attr_req_funct_comp_evid_t *this);

	/**
	 * Set flags for PTS Request Functional Component Evidence
	 *
	 * @param flags				Set of flags
	 */
	void (*set_flags)(tcg_pts_attr_req_funct_comp_evid_t *this, 
				pts_attr_req_funct_comp_evid_flag_t flags);
	
	/**
	 * Get Sub-component Depth
	 *
	 * @return				Sub-component Depth
	 */
	u_int32_t (*get_sub_component_depth)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Get Component Functional Name Vendor ID
	 *
	 * @return				Component Functional Name Vendor ID
	 */
	u_int32_t (*get_comp_funct_name_vendor_id)(tcg_pts_attr_req_funct_comp_evid_t *this);

	
	/**
	 * Get Family
	 *
	 * @return				Functional Name Encoding Family
	 */
	u_int8_t (*get_family)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Get Qualifier
	 *
	 * @return				Functional Name Category Qualifier
	 */
	u_int8_t (*get_qualifier)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Set family and qualifier for Component Functional Name
	 *
	 * @param family			Functional Name Encoding Family
	 * @param qualifier			Functional Name Category Qualifier
	 */
	void (*set_fam_qual)(tcg_pts_attr_req_funct_comp_evid_t *this, u_int8_t family,
								u_int8_t qualifier);
	
	/**
	 * Get Component Functional Name
	 *
	 * @return				Component Functional Name
	 */
	u_int32_t (*get_comp_funct_name)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	
	/**
	 * Set Component Functional Name
	 *
	 * @param name				Component Functional Name
	 */
	void (*set_comp_funct_name)(tcg_pts_attr_req_funct_comp_evid_t *this,
								u_int32_t name);
	
	
};

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object
 * 
 * @param flags				Set of flags
 * @param depth				Sub-component Depth
 * @param vendor_id			Component Functional Name Vendor ID
 * @param family			Functional Name Encoding Family
 * @param qualifier			Functional Name Category Qualifier
 * @param name				Component Functional Name
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create(pts_attr_req_funct_comp_evid_flag_t flags,
				       u_int32_t depth, 
				       u_int32_t vendor_id,
				       u_int8_t family,
				       u_int8_t qualifier,
				       u_int32_t name);

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_REQ_FUNCT_COMP_EVID_H_ @}*/
