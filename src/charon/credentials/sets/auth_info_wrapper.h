/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 *
 * $Id$
 */

/**
 * @defgroup auth_info_wrapper auth_info_wrapper
 * @{ @ingroup sets
 */

#ifndef AUTH_INFO_WRAPPER_H_
#define AUTH_INFO_WRAPPER_H_

#include <credentials/credential_set.h>
#include <credentials/auth_info.h>

typedef struct auth_info_wrapper_t auth_info_wrapper_t;

/**
 * A wrapper around auth_info_t to handle it like a credential set.
 */
struct auth_info_wrapper_t {

	/**
	 * implements credential_set_t
	 */
	credential_set_t set;
		
	/**
     * Destroy a auth_info_wrapper instance.
     */
    void (*destroy)(auth_info_wrapper_t *this);
};

/**
 * Create a auth_info_wrapper instance.
 *
 * @param auth		the wrapped auth info
 * @return			wrapper around auth
 */
auth_info_wrapper_t *auth_info_wrapper_create(auth_info_t *auth);

#endif /* AUTH_INFO_WRAPPER_H_ @}*/
