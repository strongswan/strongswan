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
 * @defgroup pts_component pts_component
 * @{ @ingroup pts
 */

#ifndef PTS_COMPONENT_H_
#define PTS_COMPONENT_H_

typedef struct pts_component_t pts_component_t;

#include "pts/components/pts_comp_func_name.h"

#include <library.h>

/**
 * PTS Functional Component Interface 
 */
struct pts_component_t {

	/**
	 * Get the PTS Component Functional Name
	 *
	 * @return				PTS Component Functional Name
	 */
	pts_comp_func_name_t* (*get_comp_func_name)(pts_component_t *this);

	/**
	 * Do measurements on the PTS Functional Component
	 *
	 * @return				TRUE if component measurements are successful
	 */
	bool (*measure)(pts_component_t *this);

	/**
	 * Verify the measurements of the PTS Functional Component
	 *
	 * @return				TRUE if verification is successful
	 */
	bool (*verify)(pts_component_t *this);

	/**
	 * Destroys a pts_component_t object.
	 */
	void (*destroy)(pts_component_t *this);

};

#endif /** PTS_COMPONENT_H_ @}*/
