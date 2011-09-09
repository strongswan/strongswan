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
 * @defgroup pts_file_meta pts_file_meta
 * @{ @ingroup pts
 */

#ifndef PTS_FILE_META_H_
#define PTS_FILE_META_H_

#include "pts_file_type.h"

#include <time.h>
#include <library.h>

typedef struct pts_file_meta_t pts_file_meta_t;
typedef struct pts_file_metadata_t pts_file_metadata_t;

/* Without filename field included */
#define PTS_FILE_METADATA_SIZE		52

/**
 * Structure holding file metadata
 */
struct pts_file_metadata_t {
	u_int16_t	  		meta_length;
	pts_file_type_t	  	type;
	u_int64_t			filesize;
	time_t				create_time;
	time_t				last_modify_time;
	time_t				last_access_time;
	u_int64_t			owner_id;
	u_int64_t			group_id;
	char				*filename;
};

/**
 * Class storing PTS File Metadata
 */
struct pts_file_meta_t {

	/**
	 * Get the number of files
	 *
	 * @return				Number of files
	 */
	int (*get_file_count)(pts_file_meta_t *this);

	/**
	 * Add a PTS File Metadata
	 *
	 * @param filename		Name of measured file or directory
	 * @param metadata		File metadata
	 */
	void (*add)(pts_file_meta_t *this, char *filename, pts_file_type_t type,
			u_int64_t filesize, time_t create_time, time_t last_modfy_time, time_t last_access_time,
			u_int64_t owner_id, u_int64_t group_id);

	/**
	  * Create a PTS File Metadata enumerator
	  *
	  * @return				Enumerator returning file metadata
	  */
	enumerator_t* (*create_enumerator)(pts_file_meta_t *this);

	/**
	 * Destroys a pts_file_meta_t object.
	 */
	void (*destroy)(pts_file_meta_t *this);

};

/**
 * Creates a pts_file_meta_t object
 */
pts_file_meta_t* pts_file_meta_create();

#endif /** PTS_FILE_MEAS_H_ @}*/
