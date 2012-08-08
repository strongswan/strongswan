/*
 * Copyright (C) 2012 Tobias Brunner
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
 * @defgroup libandroidbridge libandroidbridge
 *
 * @defgroup android_kernel kernel
 * @ingroup libandroidbridge
 *
 * @defgroup charonservice charonservice
 * @{ @ingroup libandroidbridge
 */

#ifndef CHARONSERVICE_H_
#define CHARONSERVICE_H_

#include <library.h>

typedef struct charonservice_t charonservice_t;

/**
 * Public interface of charonservice.
 *
 * Used to communicate with CharonVpnService via JNI
 */
struct charonservice_t {

	/**
	 * Install a bypass policy for the given socket using the protect() Method
	 * of the Android VpnService interface
	 *
	 * @param fd			socket file descriptor
	 * @param family		socket protocol family
	 * @return				TRUE if operation successful
	 */
	bool (*bypass_socket)(charonservice_t *this, int fd, int family);

};

/**
 * The single instance of charonservice_t.
 *
 * Set between JNI calls to initializeCharon() and deinitializeCharon().
 */
extern charonservice_t *charonservice;

#endif /** CHARONSERVICE_H_ @}*/
