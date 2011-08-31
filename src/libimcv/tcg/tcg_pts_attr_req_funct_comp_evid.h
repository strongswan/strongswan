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
typedef enum pts_attr_req_funct_comp_evid_flag_t pts_attr_req_funct_comp_evid_flag_t;

#include "tcg_attr.h"
#include "pts/pts_funct_comp_name.h"
#include "pa_tnc/pa_tnc_attr.h"

/**
 * PTS Request Functional Component Evidence Flags
 */
enum pts_attr_req_funct_comp_evid_flag_t {
	/** Transitive Trust Chain flag */
	PTS_REQ_FUNC_COMP_FLAG_TTC =				(1<<7),
	/** Verify Component flag */
	PTS_REQ_FUNC_COMP_FLAG_VER = 				(1<<6),
	/** Current Evidence flag */
	PTS_REQ_FUNC_COMP_FLAG_CURR = 				(1<<5),
	/** PCR Information flag */
	PTS_REQ_FUNC_COMP_FLAG_PCR = 				(1<<4),
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
	 * @param flags			Set of flags
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
	 * @return				Functional Name Family
	 */
	u_int8_t (*get_family)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Get Qualifier
	 *
	 * @return				Functional Name Category Qualifier
	 */
	pts_qualifier_t (*get_qualifier)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Set qualifier for Component Functional Name
	 *
	 * @param qualifier		Functional Name Category Qualifier
	 */
	void (*set_qualifier)(tcg_pts_attr_req_funct_comp_evid_t *this,
						  pts_qualifier_t qualifier);
	
	/**
	 * Get Component Functional Name
	 *
	 * @return				Component Functional Name
	 */
	pts_funct_comp_name_t (*get_comp_funct_name)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	
	/**
	 * Set Component Functional Name
	 *
	 * @param name			Component Functional Name
	 */
	void (*set_comp_funct_name)(tcg_pts_attr_req_funct_comp_evid_t *this,
								pts_funct_comp_name_t name);
	
	
};

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object
 * 
 * @param flags				Set of flags
 * @param depth				Sub-component Depth
 * @param vendor_id			Component Functional Name Vendor ID
 * @param qualifier			Functional Name Category Qualifier
 * @param name				Component Functional Name
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create(pts_attr_req_funct_comp_evid_flag_t flags,
							u_int32_t depth, u_int32_t vendor_id,
							pts_qualifier_t qualifier,
							pts_funct_comp_name_t name);

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object from received data
 *
 * @param value				Unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_REQ_FUNCT_COMP_EVID_H_ @}*/
