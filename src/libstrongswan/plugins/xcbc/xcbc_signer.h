/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup xcbc_signer xcbc_signer
 * @{ @ingroup xcbc_p
 */

#ifndef xcbc_SIGNER_H_
#define xcbc_SIGNER_H_

typedef struct xcbc_signer_t xcbc_signer_t;

#include <crypto/signers/signer.h>

/**
 * Implementation of signer_t based on CBC symmetric cypher. XCBC, RFC3566.
 */
struct xcbc_signer_t {
	
	/**
	 * generic signer_t interface for this signer
	 */
	signer_t signer_interface;
};

/**
 * Creates a new xcbc_signer_t.
 *
 * @param algo		algorithm to implement
 * @return			xcbc_signer_t, NULL if  not supported
 */
xcbc_signer_t *xcbc_signer_create(integrity_algorithm_t algo);

#endif /*xcbc_SIGNER_H_ @}*/
