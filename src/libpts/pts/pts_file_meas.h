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
 * @defgroup pts_file_meas pts_file_meas
 * @{ @ingroup pts
 */

#ifndef PTS_FILE_MEAS_H_
#define PTS_FILE_MEAS_H_

#include <library.h>

typedef struct pts_file_meas_t pts_file_meas_t;

/**
 * Class storing PTS File Measurements
 */
struct pts_file_meas_t {

	/**
	 * Get the ID of the PTS File Measurement Request
	 *
	 * @return				ID of PTS File Measurement Request
	 */
	u_int16_t (*get_request_id)(pts_file_meas_t *this);

	/**
	 * Get the number of measured files
	 *
	 * @return				Number of measured files
	 */
	int (*get_file_count)(pts_file_meas_t *this);

	/**
	 * Add a PTS File Measurement
	 *
	 * @param filename		Name of measured file or directory
	 * @param measurement	PTS Measurement hash
	 */
	void (*add)(pts_file_meas_t *this, char *filename, chunk_t measurement);

	/**
	  * Create a PTS File Measurement enumerator
	  *
	  * @return				Enumerator returning filename and measurement 
	  */
	enumerator_t* (*create_enumerator)(pts_file_meas_t *this);

	/**
	 * Verify stored hashes against PTS File Measurements
	 *
	 * @param e_hash		Hash enumerator
	 * @paraem is_dir		TRUE for directory contents hashes
	 * @return				TRUE if all hashes match a measurement
	 */
	bool (*verify)(pts_file_meas_t *this, enumerator_t *e_hash, bool is_dir);

	/**
	 * Destroys a pts_file_meas_t object.
	 */
	void (*destroy)(pts_file_meas_t *this);

};

/**
 * Creates a pts_file_meas_t object
 *
 * @param request_id		ID of PTS File Measurement Request
 */
pts_file_meas_t* pts_file_meas_create(u_int16_t request_id);

#endif /** PTS_FILE_MEAS_H_ @}*/
