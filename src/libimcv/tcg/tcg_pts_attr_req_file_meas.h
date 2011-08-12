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
 * @defgroup tcg_pts_attr_req_file_meas tcg_pts_attr_req_file_meas
 * @{ @ingroup tcg_pts_attr_req_file_meas
 */

#ifndef TCG_PTS_ATTR_REQ_FILE_MEAS_H_
#define TCG_PTS_ATTR_REQ_FILE_MEAS_H_

typedef struct tcg_pts_attr_req_file_meas_t tcg_pts_attr_req_file_meas_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"

/**
 * Class implementing the TCG PTS Request File Measurement attribute
 *
 */
struct tcg_pts_attr_req_file_meas_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;
	
	/**
	 * Get flag for PTS Request File Measurement
	 *
	 * @return				Directory Contents flag
	 */
	bool (*get_directory_flag)(tcg_pts_attr_req_file_meas_t *this);

	/**
	 * Set flag for PTS Request File Measurement
	 *
	 * @param directory_flag		Directory Contents flag
	 */
	void (*set_directory_flag)(tcg_pts_attr_req_file_meas_t *this, 
				bool directory_flag);
	
	/**
	 * Get Request ID
	 *
	 * @return				Request ID
	 */
	u_int16_t (*get_request_id)(tcg_pts_attr_req_file_meas_t *this);
	
	/**
	 * Set Request ID
	 *
	 * @param request_id			Request ID
	 */
	void (*set_request_id)(tcg_pts_attr_req_file_meas_t *this,
						u_int16_t hash_algorithm);
		
	/**
	 * Get Delimiter
	 *
	 * @return				UTF-8 encoding of a Delimiter Character
	 */
	u_int32_t (*get_delimiter)(tcg_pts_attr_req_file_meas_t *this);
	
	/**
	 * Set Delimiter 
	 *
	 * @param delimiter			UTF-8 encoding of a Delimiter Character
	 */
	void (*set_delimiter)(tcg_pts_attr_req_file_meas_t *this,
						u_int32_t delimiter);

	/**
	 * Get Fully Qualified File Path Name
	 *
	 * @return				File Path
	 */
	chunk_t (*get_file_path)(tcg_pts_attr_req_file_meas_t *this);
		
	/**
	 * Set Fully Qualified File Path Name
	 *
	 * @param path				File Path
	 */
	void (*set_file_path)(tcg_pts_attr_req_file_meas_t *this,
						chunk_t path);
	
};

/**
 * Creates an tcg_pts_attr_req_file_meas_t object
 * 
 * @param directory_flag		Directory Contents Flag
 * @param request_id			Request ID
 * @param delimiter			Delimiter Character
 * @param path				File Path
 */
pa_tnc_attr_t* tcg_pts_attr_req_file_meas_create(bool directory_flag,
				       u_int16_t request_id,
				       u_int32_t delimiter,
				       chunk_t path);

/**
 * Creates an tcg_pts_attr_req_file_meas_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_req_file_meas_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_REQ_FILE_MEAS_H_ @}*/
