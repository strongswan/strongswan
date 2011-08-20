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

#include <library.h>

/**
 * Class implementing the TCG Platform Trust System (PTS)
 *
 */
struct pts_t {

	/**
	 * get TPM 1.2 Version Info
	 *
	 * @param info	chunk containing a TPM_CAP_VERSION_INFO struct
	 * @return		TRUE if TPM Version Info available 
	 */
	bool (*get_tpm_version_info)(pts_t *this, chunk_t *info);

	/**
	 * set TPM 1.2 Version Info
	 *
	 * @param info	chunk containing a TPM_CAP_VERSION_INFO struct 
	 */
	void (*set_tpm_version_info)(pts_t *this, chunk_t info);

	/**
	 * Destroys a pts_t object.
	 */
	void (*destroy)(pts_t *this);

};

/**
 * Creates an pts_t object
 */
pts_t* pts_create(void);

#endif /** PTS_H_ @}*/
