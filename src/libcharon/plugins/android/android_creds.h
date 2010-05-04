/*
 * Copyright (C) 2010 Tobias Brunner
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

/**
 * @defgroup android_creds android_creds
 * @{ @ingroup android
 */

#ifndef ANDROID_CREDS_H_
#define ANDROID_CREDS_H_

#include <credentials/credential_set.h>

typedef struct android_creds_t android_creds_t;

/**
 * Android credentials helper.
 */
struct android_creds_t {

	/**
	 * Implements credential_set_t
	 */
	credential_set_t set;

	/**
	 * Add a trusted CA certificate from the Android keystore to serve by
	 * this set.
	 *
	 * @param name		name/ID of the certificate in the keystore
	 * @return			FALSE if the certificate does not exist or is invalid
	 */
	bool (*add_certificate)(android_creds_t *this, char *name);

	/**
	 * Set the username and password for authentication.
	 *
	 * @param id		ID of the user
	 * @param password	password to use for authentication
	 */
	void (*set_username_password)(android_creds_t *this, identification_t *id,
								  char *password);

	/**
	 * Clear the stored credentials.
	 */
	void (*clear)(android_creds_t *this);

	/**
	 * Destroy a android_creds instance.
	 */
	void (*destroy)(android_creds_t *this);

};

/**
 * Create an android_creds instance.
 */
android_creds_t *android_creds_create();

#endif /** ANDROID_CREDS_H_ @}*/
