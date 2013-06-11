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
 * @defgroup imv_os imv_os
 * @ingroup libimcv_plugins
 *
 * @defgroup imv_os_state_t imv_os_state
 * @{ @ingroup imv_os
 */

#ifndef IMV_OS_STATE_H_
#define IMV_OS_STATE_H_

#include "os_info/os_info.h"
#include <imv/imv_state.h>
#include <library.h>

typedef struct imv_os_state_t imv_os_state_t;
typedef enum imv_os_handshake_state_t imv_os_handshake_state_t;
typedef enum os_settings_t os_settings_t;

/**
 * IMV OS Handshake States (state machine)
 */
enum imv_os_handshake_state_t {
	IMV_OS_STATE_INIT,
	IMV_OS_STATE_ATTR_REQ,
	IMV_OS_STATE_POLICY_START,
	IMV_OS_STATE_WORKITEMS,
	IMV_OS_STATE_END
};

/**
 * Flags for detected OS Settings
 */
enum os_settings_t {
	OS_SETTINGS_FWD_ENABLED =         (1<<0),
	OS_SETTINGS_DEFAULT_PWD_ENABLED = (1<<1),
	OS_SETTINGS_UNKNOWN_SOURCE =      (1<<2)
};

/**
 * Internal state of an imv_os_t connection instance
 */
struct imv_os_state_t {

	/**
	 * imv_state_t interface
	 */
	imv_state_t interface;

	/**
	 * Set state of the handshake
	 *
	 * @param new_state			the handshake state of IMV
	 */
	void (*set_handshake_state)(imv_os_state_t *this,
								imv_os_handshake_state_t new_state);

	/**
	 * Get state of the handshake
	 *
	 * @return					the handshake state of IMV
	 */
	imv_os_handshake_state_t (*get_handshake_state)(imv_os_state_t *this);

	/**
	 * Set OS Product Information
	 *
	 * @param type			OS type (enumerated)
	 * @param name			OS name (string)
	 * @param version		OS version
	 */
	void (*set_info)(imv_os_state_t *this, os_type_t os_type,
					 chunk_t name, chunk_t version);

	/**
	 * Get OS Product Information
	 *
	 * @param type			OS type (enumerated)
	 * @param name			OS name (string)
	 * @param version		OS version
	 * @return				OS name & version as a concatenated string
	 */
	char* (*get_info)(imv_os_state_t *this, os_type_t *os_type,
					  chunk_t *name, chunk_t *version);

	/**
	 * Set [or with multiple attributes increment] package counters
	 *
	 * @param count				Number of processed packages
	 * @param count_update		Number of not updated packages
	 * @param count_blacklist	Number of blacklisted packages
	 * @param count_ok			Number of whitelisted packages
	 */
	void (*set_count)(imv_os_state_t *this, int count, int count_update,
					  int count_blacklist, int count_ok);

	/**
	 * Set [or with multiple attributes increment] package counters
	 *
	 * @param count				Number of processed packages
	 * @param count_update		Number of not updated packages
	 * @param count_blacklist	Number of blacklisted packages
	 * @param count_ok			Number of whitelisted packages
	 */
	void (*get_count)(imv_os_state_t *this, int *count, int *count_update,
					  int *count_blacklist, int *count_ok);

	/**
	 * Set device ID
	 *
	 * @param device_id		Device ID
	 */
	void (*set_device_id)(imv_os_state_t *this, chunk_t id);

	/**
	 * Get device ID
	 *
	 * @return				Device ID
	 */
	chunk_t (*get_device_id)(imv_os_state_t *this);

	/**
	 * Set OS settings
	 *
	 * @param settings		OS settings
	 */
	void (*set_os_settings)(imv_os_state_t *this, u_int settings);

	/**
	 * Get OS settings
	 *
	 * @return				OS settings
	 */
	u_int (*get_os_settings)(imv_os_state_t *this);

	/**
	 * Increase/Decrease the ITA Angel count
	 *
	 * @param start			TRUE increases and FALSE decreases count by one
	 */
	void (*set_angel_count)(imv_os_state_t *this, bool start);

	/**
	 * Get the ITA Angel count
	 *
	 * @return				ITA Angel count
	 */
	int (*get_angel_count)(imv_os_state_t *this);

	/**
	 * Store a bad package that has to be updated or removed
	 *
	 * @param package		Name of software package
	 * @param package_state	Security state of software package
	 */
	void (*add_bad_package)(imv_os_state_t *this, char *package,
							os_package_state_t package_state);

};

/**
 * Create an imv_os_state_t instance
 *
 * @param id			connection ID
 */
imv_state_t* imv_os_state_create(TNC_ConnectionID id);

#endif /** IMV_OS_STATE_H_ @}*/
