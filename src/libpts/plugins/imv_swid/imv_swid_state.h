/*
 * Copyright (C) 2013 Andreas Steffen
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
 * @defgroup imv_swid imv_swid
 * @ingroup libimcv_plugins
 *
 * @defgroup imv_swid_state_t imv_swid_state
 * @{ @ingroup imv_swid
 */

#ifndef IMV_SWID_STATE_H_
#define IMV_SWID_STATE_H_

#include <imv/imv_state.h>
#include <library.h>

typedef struct imv_swid_state_t imv_swid_state_t;
typedef enum imv_swid_handshake_state_t imv_swid_handshake_state_t;

/**
 * IMV OS Handshake States (state machine)
 */
enum imv_swid_handshake_state_t {
	IMV_SWID_STATE_INIT,
	IMV_SWID_STATE_WORKITEMS,
	IMV_SWID_STATE_END
};

/**
 * Internal state of an imv_swid_t connection instance
 */
struct imv_swid_state_t {

	/**
	 * imv_state_t interface
	 */
	imv_state_t interface;

	/**
	 * Set state of the handshake
	 *
	 * @param new_state			the handshake state of IMV
	 */
	void (*set_handshake_state)(imv_swid_state_t *this,
								imv_swid_handshake_state_t new_state);

	/**
	 * Get state of the handshake
	 *
	 * @return					the handshake state of IMV
	 */
	imv_swid_handshake_state_t (*get_handshake_state)(imv_swid_state_t *this);

};

/**
 * Create an imv_swid_state_t instance
 *
 * @param id			connection ID
 */
imv_state_t* imv_swid_state_create(TNC_ConnectionID id);

#endif /** IMV_SWID_STATE_H_ @}*/
