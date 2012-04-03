/*
 * Copyright (C) 2012 Tobias Brunner
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
 * @defgroup cmac_signer cmac_signer
 * @{ @ingroup cmac_p
 */

#ifndef CMAC_SIGNER_H_
#define CMAC_SIGNER_H_

typedef struct cmac_signer_t cmac_signer_t;

#include <crypto/signers/signer.h>

/**
 * Implementation of signer_t on CBC symmetric cipher using CMAC, RFC 4494.
 */
struct cmac_signer_t {

	/**
	 * Implements signer_t interface.
	 */
	signer_t signer;
};

/**
 * Creates a new cmac_signer_t.
 *
 * @param algo		algorithm to implement
 * @return			cmac_signer_t, NULL if  not supported
 */
cmac_signer_t *cmac_signer_create(integrity_algorithm_t algo);

#endif /** CMAC_SIGNER_H_ @}*/
