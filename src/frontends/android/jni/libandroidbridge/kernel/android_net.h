/*
 * Copyright (C) 2012-2013 Tobias Brunner
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
 * @defgroup android_net android_net
 * @{ @ingroup android_kernel
 */

#ifndef ANDROID_NET_H_
#define ANDROID_NET_H_

#include <library.h>

typedef struct android_net_t android_net_t;

/**
 * Handle connectivity events from NetworkManager
 */
struct android_net_t {

	/**
	 * Destroy an android_net_t instance.
	 */
	void (*destroy)(android_net_t *this);
};

/**
 * Create an android_net_t instance.
 *
 * @return			android_net_t instance
 */
android_net_t *android_net_create();

#endif /** ANDROID_NET_H_ @}*/
