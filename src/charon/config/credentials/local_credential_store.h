/**
 * @file local_credential_store.h
 *
 * @brief Interface of local_credential_store_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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
 */
 
#ifndef LOCAL_CREDENTIAL_H_
#define LOCAL_CREDENTIAL_H_

#include <types.h>
#include <daemon.h>
#include <config/credentials/credential_store.h>


typedef struct local_credential_store_t local_credential_store_t;

/**
 * @brief A credential_store_t implementation using simple credentail lists.
 *
 * The local_credential_store_t class implements the credential_store_t interface
 * as simple as possible. The credentials are stored in lists, and are loaded from
 * files on the disk.
 * Shared secret are not handled yet, so get_shared_secret always returns NOT_FOUND.
 *
 * @b Constructors:
 *  - local_credential_store_create(bool strict)
 * 
 * @ingroup config
 */
struct local_credential_store_t {
	
	/**
	 * Implements credential_store_t interface
	 */
	credential_store_t credential_store;
};

/**
 * @brief Creates a local_credential_store_t instance.
 *
 * @param  strict		enforce a strict crl policy
 * @return 				credential store instance.
 *
 * @ingroup config
 */
local_credential_store_t *local_credential_store_create(bool strict);

#endif /* LOCAL_CREDENTIAL_H_ */
