/*
 * Copyright (C) 2018 Andreas Steffen
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
 * @defgroup oqs_p oqs
 * @ingroup plugins
 *
 * @defgroup oqs_plugin oqs_plugin
 * @{ @ingroup oqs_p
 */

#ifndef OQS_PLUGIN_H_
#define OQS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct oqs_plugin_t oqs_plugin_t;

/**
 * Plugin implementing quantum-safe crypto algorithms using the OQS library.
 */
struct oqs_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Global random function used by liboqs
 *
 * @param buffer	buffer where requested random bytes are written to
 * @param size		number of requested random bytes
 */
void oqs_rand_drbg(uint8_t *buffer, size_t size);

/**
 * Sets the current DRBG used by liboqs
 *
 * @param drbg		DRBG to be used
 */
void oqs_set_drbg(drbg_t *drbg);

#endif /** OQS_PLUGIN_H_ @}*/
