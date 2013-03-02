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
 * @defgroup pa_tnc_attr_manager pa_tnc_attr_manager
 * @{ @ingroup pa_tnc
 */

#ifndef PA_TNC_ATTR_MANAGER_H_
#define PA_TNC_ATTR_MANAGER_H_

typedef struct pa_tnc_attr_manager_t pa_tnc_attr_manager_t;

#include "pa_tnc_attr.h"

#include <library.h>

typedef pa_tnc_attr_t* (*pa_tnc_attr_create_t)(u_int32_t type, chunk_t value);

/**
 * Manages PA-TNC attributes for arbitrary PENs
 */
struct pa_tnc_attr_manager_t {

	/**
	 * Add vendor-specific attribute names and creation method
	 *
	 * @param vendor_id		Private Enterprise Number (PEN)
	 * @param attr_create	Vendor-specific attribute create method
	 * @param attr_names	Vendor-specific attribute names
	 */
	void (*add_vendor)(pa_tnc_attr_manager_t *this, pen_t vendor_id,
					   pa_tnc_attr_create_t attr_create,
					   enum_name_t *attr_names);

	/**
	 * Remove vendor-specific attribute names and creation method
	 *
	 * @param vendor_id		Private Enterprise Number (PEN)
	 */
	void (*remove_vendor)(pa_tnc_attr_manager_t *this, pen_t vendor_id);

	/*
	 * Return the PA-TNC attribute names for a given vendor ID
	 *
	 * @param vendor_id		Private Enterprise Number (PEN)
	 * @return				PA-TNC attribute names if found, NULL else
	 */
	enum_name_t* (*get_names)(pa_tnc_attr_manager_t *this, pen_t vendor_id);

	/**
	 * Create a PA-TNC attribute object from data for a given vendor ID and type
	 *
	 * @param vendor_id		Private Enterprise Number (PEN)
	 * @param type			PA-TNC attribute type
	 * @param value			PA-TNC attribute value as encoded data
	 * @return				PA-TNC attribute object if supported, NULL else
	 */
	pa_tnc_attr_t* (*create)(pa_tnc_attr_manager_t *this, pen_t vendor_id,
							 u_int32_t type, chunk_t value);

	/**
	 * Destroys a pa_tnc_attr_manager_t object.
	 */
	void (*destroy)(pa_tnc_attr_manager_t *this);
};

/**
 * Create a PA-TNC attribute manager
 */
pa_tnc_attr_manager_t* pa_tnc_attr_manager_create(void);

#endif /** PA_TNC_ATTR_MANAGER_H_ @}*/
