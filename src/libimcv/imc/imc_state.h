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
 * @defgroup imc_state_t imc_state
 * @{ @ingroup imc_state
 */

#ifndef IMC_STATE_H_
#define IMC_STATE_H_

#include <tncif.h>

#include <library.h>

typedef struct imc_state_t imc_state_t;

/**
 * Internal state of an IMC connection instance
 */
struct imc_state_t {

	/**
	 * Get the TNCS connection I
D attached to the state
	 *
	 * @return				TNCS connection ID of the state
	 */
	 TNC_ConnectionID (*get_connection_id)(imc_state_t *this);

	/**
	 * Checks if long message types are supported for this TNCCS connection
	 *
	 * @return				TRUE if set, FALSE otherwise
	 */
	bool (*has_long)(imc_state_t *this);

	/**
	 * Checks if the exclusive delivery is supported for this TNCCS connection
	 *
	 * @return				TRUE if set, FALSE otherwise
	 */
	bool (*has_excl)(imc_state_t *this);

	/**
	 * Sets the long message types and exclusive flags for this TNCCS connection
	 *
	 * @param has_long		TNCCS connection supports long message types
	 * @param has_excl		TNCCS connection supports exclusive delivery
	 * @return				TRUE if set, FALSE otherwise
	 */
	void (*set_flags)(imc_state_t *this, bool has_long, bool has_excl);

	/**
	 * Change the connection state
	 *
	 * @param new_state		new connection state
	 */
	void (*change_state)(imc_state_t *this, TNC_ConnectionState new_state);

	/**
	 * Destroys an imc_state_t object
	 */
	void (*destroy)(imc_state_t *this);
};

#endif /** IMC_STATE_H_ @}*/
