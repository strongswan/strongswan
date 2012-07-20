/*
 * Copyright (C) 2012 Andreas Steffen
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
 * @defgroup pts_pcr pts_pcr
 * @{ @ingroup pts
 */

#ifndef PTS_PCR_H_
#define PTS_PCR_H_

typedef struct pts_pcr_t pts_pcr_t;

#include <library.h>

/**
 * Class implementing a shadow PCR register set
 */
struct pts_pcr_t {

	/**
	 * Get the current content of a PCR
	 *
	 * @param pcr			index of PCR
	 * @return				content of PCR
	 */
	chunk_t (*get)(pts_pcr_t *this, u_int32_t pcr);

	/**
	 * Set the content of a PCR
	 *
	 * @param pcr			index of PCR
	 * @param value			new value of PCR
	 */
	void (*set)(pts_pcr_t *this, u_int32_t pcr, chunk_t value);

	/**
	 * Extend the content of a PCR
	 *
	 * @param pcr			index of PCR
	 * @param measurement	measurment value to be extended into PCR
	 * @return				new content of PCR
	 */
	chunk_t (*extend)(pts_pcr_t *this, u_int32_t pcr, chunk_t measurement);

	/**
	 * Destroys a pts_pcr_t object.
	 */
	void (*destroy)(pts_pcr_t *this);

};

/**
 * Creates an pts_pcr_t object
 */
pts_pcr_t* pts_pcr_create(void);

#endif /** PTS_PCR_H_ @}*/
