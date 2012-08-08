/*
 * Copyright (C) 2010-2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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
 * @defgroup android_service android_service
 * @{ @ingroup android_backend
 */

#ifndef ANDROID_SERVICE_H_
#define ANDROID_SERVICE_H_

#include "android_creds.h"

#include <library.h>
#include <bus/listeners/listener.h>

typedef struct android_service_t android_service_t;

/**
 * Service that sets up an IKE_SA/CHILD_SA and handles events
 */
struct android_service_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy a android_service_t.
	 */
	void (*destroy)(android_service_t *this);

};

/**
 * Create an Android service instance. Queues a job that starts initiation of a
 * new IKE SA.
 *
 * @param local_address			local ip address
 * @param gateway				gateway address
 * @param username				user name (local identity)
 */
android_service_t *android_service_create(char *local_address, char *gateway,
										  char *username);

#endif /** ANDROID_SERVICE_H_ @}*/
