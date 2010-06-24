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
 * @defgroup android_service android_service
 * @{ @ingroup android
 */

#ifndef ANDROID_SERVICE_H_
#define ANDROID_SERVICE_H_

typedef struct android_service_t android_service_t;

#include <bus/listeners/listener.h>

#include "android_creds.h"

/**
 * Service that interacts with the Android Settings frontend.
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
 * Create an Android service instance.
 *
 * @param creds		Android credentials
 */
android_service_t *android_service_create(android_creds_t *creds);

#endif /** ANDROID_SERVICE_H_ @}*/
