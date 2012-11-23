/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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
 *
 * @defgroup imv_scanner_state_t imv_scanner_state
 * @{ @ingroup imv_scanner_state
 */

#ifndef IMV_SCANNER_STATE_H_
#define IMV_SCANNER_STATE_H_

#include <imv/imv_state.h>
#include <library.h>

typedef struct imv_scanner_state_t imv_scanner_state_t;

/**
 * Internal state of an imv_scanner_t connection instance
 */
struct imv_scanner_state_t {

	/**
	 * imv_state_t interface
	 */
	imv_state_t interface;

	/**
	 * add a violating TCP or UDP port
	 */
	void (*add_violating_port)(imv_scanner_state_t *this, char *port);
};

/**
 * Create an imv_scanner_state_t instance
 *
 * @param id			connection ID
 */
imv_state_t* imv_scanner_state_create(TNC_ConnectionID id);

#endif /** IMV_SCANNER_STATE_H_ @}*/
