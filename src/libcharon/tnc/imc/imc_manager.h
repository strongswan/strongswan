/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup imc_manager imc_manager
 * @{ @ingroup imc
 */

#ifndef IMC_MANAGER_H_
#define IMC_MANAGER_H_

#include "imc.h"

#include <library.h>

typedef struct imc_manager_t imc_manager_t;

/**
 * The IMC manager controls all IMC instances.
 */
struct imc_manager_t {

	/**
	 * Add an IMC instance
	 *
	 * @param imc			IMC instance
	 * @return				TRUE if initialization successful
	 */
	 bool (*add)(imc_manager_t *this, imc_t *imc);

	/**
	 * Notify all IMC instances
	 *
	 * @param state			communicate the state a connection has reached
	 */
	void (*notify_connection_change)(imc_manager_t *this,
									 TNC_ConnectionID id,
									 TNC_ConnectionState state);

	/**
	 * Begin a handshake between the IMCs and a connection
	 *
	 * @param id			Connection ID
	 */
	void (*begin_handshake)(imc_manager_t *this, TNC_ConnectionID id);

	/**
	 * Destroy an IMC manager and all its controlled instances.
	 */
	void (*destroy)(imc_manager_t *this);
};

#endif /** IMC_MANAGER_H_ @}*/
