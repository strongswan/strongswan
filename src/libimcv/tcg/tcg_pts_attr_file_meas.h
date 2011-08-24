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
 * @defgroup tcg_pts_attr_file_meas tcg_pts_attr_file_meas
 * @{ @ingroup tcg_pts_attr_file_meas
 */

#ifndef TCG_PTS_ATTR_FILE_MEAS_H_
#define TCG_PTS_ATTR_FILE_MEAS_H_

typedef struct tcg_pts_attr_file_meas_t tcg_pts_attr_file_meas_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"
/* TODO: for struct file_meas_entry_t */
#include "pts/pts.h"

/**
 * Class implementing the TCG PTS File Measurement attribute
 *
 */
struct tcg_pts_attr_file_meas_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;
		
	/**
	 * Get Number of Files included
	 *
	 * @return				Number of Files included
	 */
	u_int64_t (*get_number_of_files)(tcg_pts_attr_file_meas_t *this);
	
	/**
	 * Set Number of Files included
	 *
	 * @param num_files			Number of Files included
	 */
	void (*set_number_of_files)(tcg_pts_attr_file_meas_t *this,
						u_int64_t num_files);
	
	/**
	 * Get Request ID
	 *
	 * @return				Request ID
	 */
	u_int16_t (*get_request_id)(tcg_pts_attr_file_meas_t *this);
	
	/**
	 * Set Request ID
	 *
	 * @param request_id			Request ID
	 */
	void (*set_request_id)(tcg_pts_attr_file_meas_t *this,
						u_int16_t request_id);
		
	/**
	 * Get Measurement Length
	 *
	 * @return				Measurement Length
	 */
	u_int16_t (*get_meas_len)(tcg_pts_attr_file_meas_t *this);
	
	/**
	 * Set Measurement Length 
	 *
	 * @param meas_len			Measurement Length
	 */
	void (*set_meas_len)(tcg_pts_attr_file_meas_t *this,
						u_int16_t meas_len);
	
	 /**
	 * Add a file measurement entry
	 *
	 * @param measurement		Measurement value
	 * @param file_name		File Name
	 */
	void (*add_file_meas)(tcg_pts_attr_file_meas_t *this, chunk_t measurement,
						chunk_t file_name);

	/**
	 * Enumerates over all file measurements
	 * Format:  chunk_t *measurement, chunk_t *file_name
	 *
	 * @return				enumerator
	 */
	enumerator_t* (*create_file_meas_enumerator)(tcg_pts_attr_file_meas_t *this);
};

/**
 * Creates an tcg_pts_attr_file_meas_t object
 * 
 * @param directory_flag		Directory Contents Flag
 * @param request_id			Request ID
 * @param delimiter			Delimiter Character
 * @param path				File Path
 */
pa_tnc_attr_t* tcg_pts_attr_file_meas_create(u_int64_t number_of_files,
				       u_int16_t request_id,
				       u_int16_t meas_len);

/**
 * Creates an tcg_pts_attr_file_meas_t object from received data
 *
 * @param value				unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_file_meas_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_FILE_MEAS_H_ @}*/
