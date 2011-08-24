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
 * @defgroup pts pts
 * @{ @ingroup pts
 */

#ifndef PTS_H_
#define PTS_H_

typedef struct pts_t pts_t;

#include "pts_proto_caps.h"
#include "pts_meas_algo.h"
#include <utils/linked_list.h>

#include <library.h>

typedef struct measurement_req_entry_t measurement_req_entry_t;
typedef struct file_meas_entry_t file_meas_entry_t;

/**
 * File Measurement entry
 */
struct file_meas_entry_t {
	chunk_t   measurement;
	u_int16_t file_name_len;
	chunk_t   file_name;
};

/**
 * Class implementing the TCG Platform Trust System (PTS)
 *
 */
struct pts_t {

	/**
	 * Get PTS Protocol Capabilities
	 *
	 * @return				protocol capabilities flags 
	 */
	pts_proto_caps_flag_t (*get_proto_caps)(pts_t *this);

	/**
	 * Set PTS Protocol Capabilities
	 *
	 * @param flags			protocol capabilities flags 
	 */
	void (*set_proto_caps)(pts_t *this, pts_proto_caps_flag_t flags);

	/**
	 * Get PTS Measurement Algorithm
	 *
	 * @return				measurement algorithm 
	 */
	pts_meas_algorithms_t (*get_meas_algorithm)(pts_t *this);

	/**
	 * Set PTS Measurement Algorithm
	 *
	 * @param algorithm		measurement algorithm 
	 */
	void (*set_meas_algorithm)(pts_t *this, pts_meas_algorithms_t algorithm);

	/**
	 * Get TPM 1.2 Version Info
	 *
	 * @param info			chunk containing a TPM_CAP_VERSION_INFO struct
	 * @return				TRUE if TPM Version Info available 
	 */
	bool (*get_tpm_version_info)(pts_t *this, chunk_t *info);

	/**
	 * Set TPM 1.2 Version Info
	 *
	 * @param info			chunk containing a TPM_CAP_VERSION_INFO struct 
	 */
	void (*set_tpm_version_info)(pts_t *this, chunk_t info);
	
	/**
	 * Hash the given file
	 *
	 * @param path			absolute path to file to be hashed
	 * @param out			hash output value of a given file
	 * @return			TRUE if hashing file was successful 
	 */
	bool (*hash_file)(pts_t *this, char *path, char *out);
	
	/**
	 * Hash the given directory
	 *
	 * @param path			absolute path to directory to be hashed
	 * @param file_measurements	list of hash output values of files in a given folder
	 * @return			TRUE if hashing directory was successful 
	 */
	bool (*hash_directory)(pts_t *this, char *path, linked_list_t *file_measurements);

	/**
	 * Destroys a pts_t object.
	 */
	void (*destroy)(pts_t *this);

};

/**
 * Creates an pts_t object
 *
 * @param is_imc			TRUE if running on an IMC
 */
pts_t* pts_create(bool is_imc);

#endif /** PTS_H_ @}*/
