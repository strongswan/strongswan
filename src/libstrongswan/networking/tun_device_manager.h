/*
 * Copyright (C) 2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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
* @defgroup tun_device_manager tun_device_manager
* @{ @ingroup tun_device
*/

#ifndef TUN_DEVICE_MANAGER_H_
#define TUN_DEVICE_MANAGER_H_

typedef struct tun_device_manager_t tun_device_manager_t;

#include <networking/tun_device.h>

/**
 * The tun_device_manager manages the TUN device implementations and
 * creates instances of them.
 *
 * A tun device plugin is registered by providing its constructor function
 * to the manager. The manager creates instances of the tun device plugin
 * using the registered constructor function.
 *
 * Currently the default POSIX TUN device is not a plugin, but hard-coded
 * into libstrongswan. If no third party TUN device plugin is registered, then
 * the built-in POSIX tun device is used.
 */
struct tun_device_manager_t {

	/**
	 * Register a TUN_device implementation.
	 *
	 * @param constructor	tun_device constructor function
	 */
	void (*add_tun_device)(tun_device_manager_t *this,
						   tun_device_constructor_t constructor);

	/**
	 * Unregister a previously registered tun_device implementation.
	 *
	 * @param constructor tun_device constructor function to unregister
	 */
	void (*remove_tun_device)(tun_device_manager_t *this,
							  tun_device_constructor_t constructor);

	/**
	 * Get a new tun_device instance.
	 *
	 * @param name_tmpl		name template, defaults to "tun%d" if not given
	 * @return 				tun_device instance.
	 */
	tun_device_t* (*create)(tun_device_manager_t *this, const char *name_tmpl);

	/**
	 * Destroy a tun_device_manager instance.
	 */
	void (*destroy)(tun_device_manager_t *this);
};

/**
 * Create a tun_device_manager instance.
 */
tun_device_manager_t *tun_device_manager_create();

#endif /** TUN_DEVICE_MANAGER_H_ @}*/
