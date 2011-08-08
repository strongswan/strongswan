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
 * @defgroup tcg_pts_attr_meas_algo_selection tcg_pts_attr_meas_algo_selection
 * @{ @ingroup tcg_pts_attr_meas_algo_selection
 */

#ifndef TCG_PTS_ATTR_MEAS_ALGO_SELECTION_H_
#define TCG_PTS_ATTR_MEAS_ALGO_SELECTION_H_

typedef struct tcg_pts_attr_meas_algo_selection_t tcg_pts_attr_meas_algo_selection_t;
typedef enum pts_attr_meas_algorithms_t pts_attr_meas_algorithms_t;

#include "tcg_attr.h"
#include "pa_tnc/pa_tnc_attr.h"

/**
 * PTS Measurement Algorithms
 */
enum pts_attr_meas_algorithms_t {
	/** SHA-384 */
	PTS_MEAS_ALGO_SHA1 =				(1<<0),
	/** SHA-256 */
	PTS_MEAS_ALGO_SHA256 = 				(1<<1),
	/** SHA-1 */
	PTS_MEAS_ALGO_SHA384 = 				(1<<2),
};

/**
 * Class implementing the TCG Measurement Algorithm Selection Attribute
 *
 */
struct tcg_pts_attr_meas_algo_selection_t {

	/**
	 * Public PA-TNC attribute interface
	 */
	pa_tnc_attr_t pa_tnc_attribute;

	/**
	 * Get a selected PTS Measurement Algorithm
	 *
	 * @return				A Selected Measurement Algorithm
	 */
	pts_attr_meas_algorithms_t (*get_algorithm)(tcg_pts_attr_meas_algo_selection_t *this);

	/**
	 * Set PTS Measurement Algorithm
	 *
	 * @param flags				A Selected Measurement Algorithm
	 */
	void (*set_algorithm)(tcg_pts_attr_meas_algo_selection_t *this, 
			  pts_attr_meas_algorithms_t algorithm);
	
};

/**
 * Creates an tcg_pts_attr_meas_algo_selection_t object
 *
 * @param algorithm				A Selected Measurement Algorithm
 */
pa_tnc_attr_t* tcg_pts_attr_meas_algo_selection_create(pts_attr_meas_algorithms_t algorithm);

/**
 * Creates an tcg_pts_attr_meas_algo_selection_t object from received data
 *
 * @param value					unparsed attribute value
 */
pa_tnc_attr_t* tcg_pts_attr_meas_algo_selection_create_from_data(chunk_t value);

#endif /** TCG_PTS_ATTR_MEAS_ALGO_H_ @}*/
