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
 * @defgroup android_backend backend
 * @ingroup libandroidbridge
 *
 * @defgroup android_kernel kernel
 * @ingroup libandroidbridge
 *
 * @defgroup charonservice charonservice
 * @{ @ingroup libandroidbridge
 */

#ifndef CHARONSERVICE_H_
#define CHARONSERVICE_H_

#include "vpnservice_builder.h"

#include <library.h>
#include <utils/linked_list.h>

typedef enum android_vpn_state_t android_vpn_state_t;
typedef struct charonservice_t charonservice_t;

/**
 * VPN status codes. As defined in CharonVpnService.java
 */
enum android_vpn_state_t {
	CHARONSERVICE_CHILD_STATE_UP = 1,
	CHARONSERVICE_CHILD_STATE_DOWN,
	CHARONSERVICE_AUTH_ERROR,
	CHARONSERVICE_PEER_AUTH_ERROR,
	CHARONSERVICE_LOOKUP_ERROR,
	CHARONSERVICE_UNREACHABLE_ERROR,
	CHARONSERVICE_GENERIC_ERROR,
};

/**
 * Public interface of charonservice.
 *
 * Used to communicate with CharonVpnService via JNI
 */
struct charonservice_t {

	/**
	 * Update the status in the Java domain (UI)
	 *
	 * @param code			status code
	 * @return				TRUE on success
	 */
	bool (*update_status)(charonservice_t *this, android_vpn_state_t code);

	/**
	 * Install a bypass policy for the given socket using the protect() Method
	 * of the Android VpnService interface
	 *
	 * @param fd			socket file descriptor
	 * @param family		socket protocol family
	 * @return				TRUE if operation successful
	 */
	bool (*bypass_socket)(charonservice_t *this, int fd, int family);

	/**
	 * Get a list of trusted certificates via JNI
	 *
	 * @return				list of DER encoded certificates (as chunk_t*),
	 *						NULL on failure
	 */
	linked_list_t *(*get_trusted_certificates)(charonservice_t *this);

	/**
	 * Get the current vpnservice_builder_t object
	 *
	 * @return				VpnService.Builder instance
	 */
	vpnservice_builder_t *(*get_vpnservice_builder)(charonservice_t *this);

};

/**
 * The single instance of charonservice_t.
 *
 * Set between JNI calls to initializeCharon() and deinitializeCharon().
 */
extern charonservice_t *charonservice;

#endif /** CHARONSERVICE_H_ @}*/
