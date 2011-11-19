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
 * @defgroup pts_funct_comp_evid_req pts_funct_comp_evid_req
 * @{ @ingroup pts
 */

#ifndef PTS_FUNCT_COMP_EVID_REQ_H_
#define PTS_FUNCT_COMP_EVID_REQ_H_

typedef struct pts_funct_comp_evid_req_t pts_funct_comp_evid_req_t;
typedef enum pts_attr_req_funct_comp_evid_flag_t pts_attr_req_funct_comp_evid_flag_t;
typedef struct funct_comp_evid_req_entry_t funct_comp_evid_req_entry_t;

#include "pts/components/pts_comp_func_name.h"

#include <library.h>

#define PTS_REQ_FUNCT_COMP_FAM_BIN_ENUM		0x00

/**
 * PTS Request Functional Component Evidence Flags
 */
enum pts_attr_req_funct_comp_evid_flag_t {
	/** Transitive Trust Chain flag */
	PTS_REQ_FUNC_COMP_FLAG_TTC =				(1<<7),
	/** Verify Component flag */
	PTS_REQ_FUNC_COMP_FLAG_VER =				 (1<<6),
	/** Current Evidence flag */
	PTS_REQ_FUNC_COMP_FLAG_CURR =				 (1<<5),
	/** PCR Information flag */
	PTS_REQ_FUNC_COMP_FLAG_PCR =				 (1<<4),
};

/**
 * PTS Functional Component Evidence Request entry
 */
struct funct_comp_evid_req_entry_t {
	pts_attr_req_funct_comp_evid_flag_t flags;
	u_int32_t sub_comp_depth;
	pts_comp_func_name_t *name;
};

/**
 * Class storing PTS Functional Component Evidence Request
 */
struct pts_funct_comp_evid_req_t {

	/**
	 * Get the number of requested components
	 *
	 * @return				Number of requested components
	 */
	int (*get_req_count)(pts_funct_comp_evid_req_t *this);

	/**
	 * Add a PTS File Measurement
	 *
	 * @param entry			PTS Functional Component Evidence Request entry		
	 */
	void (*add)(pts_funct_comp_evid_req_t *this,
									funct_comp_evid_req_entry_t *entry);

	/**
	  * Create a PTS Functional Component Evidence Request enumerator
	  *
	  * @return				Enumerator returning flags, sub-component depth and
	  *						functional component name 
	  */
	enumerator_t* (*create_enumerator)(pts_funct_comp_evid_req_t *this);

	/**
	 * Destroys a pts_funct_comp_evid_req_t object.
	 */
	void (*destroy)(pts_funct_comp_evid_req_t *this);

};

/**
 * Creates a pts_funct_comp_evid_req_t object
 */
pts_funct_comp_evid_req_t* pts_funct_comp_evid_req_create();

#endif /** PTS_FUNCT_COMP_EVID_REQ_H_ @}*/
