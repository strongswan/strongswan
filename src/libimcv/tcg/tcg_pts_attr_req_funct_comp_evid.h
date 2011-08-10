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
typedef enum pts_attr_req_funct_comp_type_t pts_attr_req_funct_comp_type_t;
typedef enum pts_attr_req_funct_comp_name_bin_enum_t pts_attr_req_funct_comp_name_bin_enum_t;
typedef struct tcg_pts_qualifier_t tcg_pts_qualifier_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"

/**
 * PTS Request Functional Component Evidence Flags
 */
enum pts_attr_req_funct_comp_evid_flag_t {
	/** Transitive Trust Chain flag */
	PTS_REQ_FUNC_COMP_FLAG_TTC =				(1<<0),
	/** Verify Component flag */
	PTS_REQ_FUNC_COMP_FLAG_VER = 				(1<<1),
	/** Current Evidence flag */
	PTS_REQ_FUNC_COMP_FLAG_CURR = 				(1<<2),
	/** PCR Information flag */
	PTS_REQ_FUNC_COMP_FLAG_PCR = 				(1<<3),
};

/**
 * PTS Component Functional Type for Qualifier field
 */
enum pts_attr_req_funct_comp_type_t {
	/** Unknown */
	PTS_FUNC_COMP_TYPE_UNKNOWN =				0x0,
	/** Trusted Platform */
	PTS_FUNC_COMP_TYPE_TRUSTED = 				0x1,
	/** Operating System */
	PTS_FUNC_COMP_TYPE_OS = 				0x2,
	/** Graphical User Interface */
	PTS_FUNC_COMP_TYPE_GUI = 				0x3,
	/** Application */
	PTS_FUNC_COMP_TYPE_APP =				0x4,
	/** Networking */
	PTS_FUNC_COMP_TYPE_NET = 				0x5,
	/** Library */
	PTS_FUNC_COMP_TYPE_LIB = 				0x6,
	/** TNC Defined Component */
	PTS_FUNC_COMP_TYPE_TNC = 				0x7,
	/** All matching Components */
	PTS_FUNC_COMP_TYPE_ALL = 				0xF,
};

/**
 * PTS Component Functional Name Binary Enumeration
 */
enum pts_attr_req_funct_comp_name_bin_enum_t {
	/** Ignore */
	PTS_FUNC_COMP_NAME_IGNORE =				0x0000,
	/** CRTM */
	PTS_FUNC_COMP_NAME_CRTM = 				0x0001,
	/** BIOS */
	PTS_FUNC_COMP_NAME_BIOS = 				0x0002,
	/** Platform Extensions */
	PTS_FUNC_COMP_NAME_PLAT_EXT = 				0x0003,
	/** Motherboard firmware */
	PTS_FUNC_COMP_NAME_BOARD =				0x0004,
	/** Initial Program Loader */
	PTS_FUNC_COMP_NAME_INIT_LOADER = 			0x0005,
	/** Option ROMs */
	PTS_FUNC_COMP_NAME_OPT_ROMS = 				0x0006,
};

/**
 * Qualifier for Functional Component
 */
struct tcg_pts_qualifier_t {
	bool      kernel;
	bool      sub_component;
	pts_attr_req_funct_comp_type_t  type;
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
	 * @return				Functional Name Family
	 */
	u_int8_t (*get_family)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Get Qualifier
	 *
	 * @return				Functional Name Category Qualifier
	 */
	tcg_pts_qualifier_t (*get_qualifier)(tcg_pts_attr_req_funct_comp_evid_t *this);
	
	/**
	 * Set qualifier for Component Functional Name
	 *
	 * @param qualifier			Functional Name Category Qualifier
	 */
	void (*set_qualifier)(tcg_pts_attr_req_funct_comp_evid_t *this,
						tcg_pts_qualifier_t qualifier);
	
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
 * @param qualifier			Functional Name Category Qualifier
 * @param name				Component Functional Name
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create(pts_attr_req_funct_comp_evid_flag_t flags,
				       u_int32_t depth, 
				       u_int32_t vendor_id,
				       tcg_pts_qualifier_t qualifier,
				       u_int32_t name);

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_REQ_FUNCT_COMP_EVID_H_ @}*/
