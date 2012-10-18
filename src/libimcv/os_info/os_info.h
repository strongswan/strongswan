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
 * @defgroup os_info os_info
 * @{ @ingroup libimcv
 */

#ifndef OS_INFO_H_
#define OS_INFO_H_

typedef struct os_info_t os_info_t;
typedef enum os_fwd_status_t os_fwd_status_t;

#include <library.h>

#include <time.h>

/**
 * Defines the IPv4 forwarding status
 */
enum os_fwd_status_t {
	OS_FWD_DISABLED =	0,
	OS_FWD_ENABLED =	1,
	OS_FWD_UNKNOWN =	2
};

extern enum_name_t *os_fwd_status_names;

/**
 * Interface for the Operating System (OS) information module
 */
struct os_info_t {

	/**
	 * Get the OS product name or distribution
	 *
	 * @return					OS name
	 */
	chunk_t (*get_name)(os_info_t *this);

	/**
	 * Get the numeric OS version or release
	 *
	 * @param major				OS major version number
	 * @param minor				OS minor version number
	 */
	void (*get_numeric_version)(os_info_t *this, u_int32_t *major,
												 u_int32_t *minor);

	/**
	 * Get the OS version or release
	 *
	 * @return					OS version
	 */
	chunk_t (*get_version)(os_info_t *this);

	/**
	 * Get the OS IPv4 forwarding status
	 *
	 * @return					IP forwarding status
	 */
	os_fwd_status_t (*get_fwd_status)(os_info_t *this);

	/**
	 * Get the OS uptime in seconds
	 *
	 * @return					OS uptime
	 */
	time_t (*get_uptime)(os_info_t *this);

	/**
	 * Enumerates over all installed packages
	 *
	 * @return				return package enumerator
	 */
	enumerator_t* (*create_package_enumerator)(os_info_t *this);

	/**
	 * Destroys an os_info_t object.
	 */
	void (*destroy)(os_info_t *this);
};

/**
 * Create an os_info_t object
 */
os_info_t* os_info_create(void);

#endif /** OS_INFO_H_ @}*/
