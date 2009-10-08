/*
 * Copyright (C) 2008-2009 Martin Willi
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
 * @defgroup eap_aka_3gpp2_functions eap_aka_3gpp2_functions
 * @{ @ingroup eap_aka_3gpp2
 */

#ifndef EAP_AKA_3GPP2_FUNCTIONS_H_
#define EAP_AKA_3GPP2_FUNCTIONS_H_

#include <utils/enumerator.h>
#include <utils/identification.h>

typedef struct eap_aka_3gpp2_functions_t eap_aka_3gpp2_functions_t;

/**
 * f1-f5(), f1*() and f5*() functions from the 3GPP2 (S.S0055) standard.
 */
struct eap_aka_3gpp2_functions_t {

	/**
	 * Destroy a eap_aka_3gpp2_functions_t.
	 */
	void (*destroy)(eap_aka_3gpp2_functions_t *this);
};

/**
 * Create a eap_aka_3gpp2_functions instance.
 */
eap_aka_3gpp2_functions_t *eap_aka_3gpp2_functions_create();

#endif /** EAP_AKA_3GPP2_FUNCTIONS_ @}*/
