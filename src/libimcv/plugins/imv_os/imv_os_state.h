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
typedef enum os_settings_t os_settings_t;

enum os_settings_t {
	OS_SETTINGS_FWD_ENABLED =         1,
	OS_SETTINGS_DEFAULT_PWD_ENABLED = 2,
	OS_SETTINGS_NON_MARKET_APPS =     4
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
	 * Set/reset OS Installed Packages request status
	 *
	 * @param set			TRUE to set, FALSE to clear
	 */
	void (*set_package_request)(imv_os_state_t *this, bool set);

	/**
	 * Get OS Installed Packages request status
	 *
	 * @return				TRUE if set, FALSE if unset
	 */
	bool (*get_package_request)(imv_os_state_t *this);

	/**
	 * Set device ID
	 *
	 * @param device_id		Device ID primary database key
	 */
	void (*set_device_id)(imv_os_state_t *this, int id);

	/**
	 * Get device ID
	 *
	 * @return				Device ID primary database key
	 */
	int (*get_device_id)(imv_os_state_t *this);

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
