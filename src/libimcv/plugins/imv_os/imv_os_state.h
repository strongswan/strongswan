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
	 * @param name		OS name
	 * @param version	OS version
	 */
	void (*set_info)(imv_os_state_t *this, chunk_t name, chunk_t version);

	/**
	 * Get OS Product Information
	 *
	 * @result			OS name & version
	 */
	char* (*get_info)(imv_os_state_t *this);

};

/**
 * Create an imv_os_state_t instance
 *
 * @param id			connection ID
 */
imv_state_t* imv_os_state_create(TNC_ConnectionID id);

#endif /** IMV_OS_STATE_H_ @}*/
