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

#include "tcg_attr.h"
#include "pts/pts_funct_comp_name.h"
#include "pts/pts_funct_comp_evid_req.h"
#include "pa_tnc/pa_tnc_attr.h"


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
	 * Get PTS Functional Component Evidence Requests
	 *
	 * @return					PTS Functional Component Evidence Requests
	 */
	pts_funct_comp_evid_req_t* (*get_requests)(
									tcg_pts_attr_req_funct_comp_evid_t *this);
	
	
};

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object
 * 
 * @param requests	Linked list of PTS Functional Component Evidence Requests
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create(
										pts_funct_comp_evid_req_t *requests);

/**
 * Creates an tcg_pts_attr_req_funct_comp_evid_t object from received data
 *
 * @param value				Unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_req_funct_comp_evid_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_REQ_FUNCT_COMP_EVID_H_ @}*/
