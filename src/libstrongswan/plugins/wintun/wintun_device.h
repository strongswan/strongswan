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
 * @defgroup wintun_device wintun_device
 * @{ @ingroup wintun_p
 */

#ifndef WINTUN_DEVICE_H_
#define WINTUN_DEVICE_H_

#include <networking/tun_device.h>

typedef struct wintun_device_t wintun_device_t;

/**
 * Windows TUN device implementation
  */
struct wintun_device_t {

	/**
	 * Generic tun_device_t interface.
	 */
	tun_device_t tun;
};

/**
 * Create a Windows TUN device using the given name template.
 *
 * @param name_tmpl         name template, defaults to "tun%d" if not given
 * @return                  Windows TUN device
 */
wintun_device_t *wintun_device_create(const char *name_tmpl);

/**
 * Initialize wintun library.
 *
 * @return              FALSE if library initialization failed
 */
bool wintun_library_init();

/**
 * Deinitialize wintun library.
 */
void wintun_library_deinit();

#endif /** WINTUN_DEVICE_H_ @}*/
