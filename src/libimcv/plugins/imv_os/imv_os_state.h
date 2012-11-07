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
 *
 * @defgroup imv_os_state_t imv_os_state
 * @{ @ingroup imv_os_state
 */

#ifndef IMV_OS_STATE_H_
#define IMV_OS_STATE_H_

#include "os_info/os_info.h"
#include <imv/imv_state.h>
#include <library.h>

typedef struct imv_os_state_t imv_os_state_t;

/**
 * Internal state of an imv_os_t connection instance
 */
struct imv_os_state_t {

	/**
	 * imv_state_t interface
	 */
	imv_state_t interface;

	/**
	 * Set OS Product Information
	 *
	 * @param type		OS type (enumerated)
	 * @param name		OS name (string)
	 * @param version	OS version
	 */
	void (*set_info)(imv_os_state_t *this, os_type_t os_type,
					 chunk_t name, chunk_t version);

	/**
	 * Get OS Product Information
	 *
	 * @param type		OS type (enumerated)
	 * @param name		OS name (string)
	 * @param version	OS version
	 * @result			OS name & version as a concatenated string 
	 */
	char* (*get_info)(imv_os_state_t *this, os_type_t *os_type,
					  chunk_t *name, chunk_t *version);

	/**
	 * Set/reset OS Installed Packages request status
	 *
	 * @param set		TRUE to set, FALSE to clear
	 */
	void (*set_package_request)(imv_os_state_t *this, bool set);

	/**
	 * Get OS Installed Packages request status
	 *
	 * @result			TRUE if set, FALSE if unset
	 */
	bool (*get_package_request)(imv_os_state_t *this);

	/**
	 * Increase/Decrease the ITA Angel count
	 *
	 * @param start			TRUE increases and FALSE decreases count by one
	 */
	void (*set_angel_count)(imv_os_state_t *this, bool start);

	/**
	 * Get the ITA Angel count
	 *
	 * @result			ITA Angel count
	 */
	int (*get_angel_count)(imv_os_state_t *this);

};

/**
 * Create an imv_os_state_t instance
 *
 * @param id			connection ID
 */
imv_state_t* imv_os_state_create(TNC_ConnectionID id);

#endif /** IMV_OS_STATE_H_ @}*/
