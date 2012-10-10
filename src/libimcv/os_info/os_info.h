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

#include <library.h>

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
	 * Get the OS version or release
	 *
	 * @return					OS version
	 */
	chunk_t (*get_version)(os_info_t *this);

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
