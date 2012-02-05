/*
 * Copyright (C) 2011 Andreas Steffen
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
 * @defgroup pts_database pts_database
 * @{ @ingroup pts
 */

#ifndef PTS_DATABASE_H_
#define PTS_DATABASE_H_

typedef struct pts_database_t pts_database_t;

#include "pts_meas_algo.h"
#include "components/pts_comp_func_name.h"
#include <library.h>

/**
 * Class implementing the PTS File Measurement database
 *
 */
struct pts_database_t {

	/**
	* Get files/directories to be measured by PTS
	*
	* @param product		Software product (os, vpn client, etc.)
	* @return				Enumerator over all matching files/directories
	*/
	enumerator_t* (*create_file_meas_enumerator)(pts_database_t *this,
												 char *product);

	/**
	* Get files/directories to request metadata of
	*
	* @param product		Software product (os, vpn client, etc.)
	* @return				Enumerator over all matching files/directories
	*/
	enumerator_t* (*create_file_meta_enumerator)(pts_database_t *this,
												 char *product);

	/**
	* Get stored measurement hash for single file or directory entries
	*
	* @param product		Software product (os, vpn client, etc.)
	* @param algo			Hash algorithm used for measurement
	* @param id				Primary key of measured file/directory
	* @param is_dir			TRUE if directory was measured
	* @return				Enumerator over all matching measurement hashes
	*/
	enumerator_t* (*create_file_hash_enumerator)(pts_database_t *this,
								char *product, pts_meas_algorithms_t algo,
								int id, bool is_dir);

	/**
	* Check if an AIK given by its keyid is registered in the database
	*
	* @param keyid			AIK keyid (SHA-1 hash of the AIK public key info)
	* @param kid			Primary key of AIK entry in keys table
	* @return				SUCCESS if AIK is present, FAILED otherwise
	*/
	status_t (*check_aik_keyid)(pts_database_t *this, chunk_t keyid, int *kid);

	/**
	* Get functional components to request evidence of
	*
	* @param kid			Primary key of AIK entry in keys table
	* @return				Enumerator over all matching components
	*/
	enumerator_t* (*create_comp_evid_enumerator)(pts_database_t *this, int kid);

	/**
	* Check a functional component measurement against value stored in database
	*
	* @param measurement	measurement hash
	* @param cid			Primary key of Component Functional Name entry
	* @param kid			Primary key of AIK entry in keys table
	* @param seq_no			Measurement sequence number
	* @param prc			Number of the PCR the measurement was extended into
	* @param algo			Hash algorithm used for measurement
	* @return				SUCCESS if check was successful
	*/
	status_t (*check_comp_measurement)(pts_database_t *this, chunk_t measurement,
									   int cid, int kid, int seq_no, int pcr,
									   pts_meas_algorithms_t algo);

	/**
	* Insert a functional component measurement into the database
	*
	* @param measurement	Measurement hash
	* @param cid			Primary key of Component Functional Name entry
	* @param kid			Primary key of AIK entry in keys table
	* @param seq_no			Measurement sequence number
	* @param prc			Number of the PCR the measurement was extended into
	* @param algo			Hash algorithm used for measurement
	* @return				SUCCESS if INSERT was successful
	*/
	status_t (*insert_comp_measurement)(pts_database_t *this, chunk_t measurement,
										int cid, int kid, int seq_no, int pcr,
										pts_meas_algorithms_t algo);

	/**
	* Delete functional component measurements from the database
	*
	* @param cid			Primary key of Component Functional Name entry
	* @param kid			Primary key of AIK entry in keys table
	* @return				number of deleted measurement entries
	*/
	int (*delete_comp_measurements)(pts_database_t *this, int cid, int kid);

	/**
	* Get the number of measurements for a functional component and AIK
	*
	* @param comp_name		Component Functional Name
	* @param keyid			SHA-1 hash of AIK public key info
	* @param algo			Hash algorithm used for measurement
	* @param cid			Primary key of Component Functional Name entry
	* @param kid			Primary key of AIK entry in keys table
	* @param count			measurement count
	* @return				SUCCESS if COUNT was successful
	*/
	status_t (*get_comp_measurement_count)(pts_database_t *this,
							pts_comp_func_name_t *comp_name, chunk_t keyid,
							pts_meas_algorithms_t algo, int *cid, int *kid,
							int *count);

	/**
	* Destroys a pts_database_t object.
	*/
	void (*destroy)(pts_database_t *this);

};

/**
 * Creates an pts_database_t object
 *
 * @param uri				database uri
 */
pts_database_t* pts_database_create(char *uri);

#endif /** PTS_DATABASE_H_ @}*/
