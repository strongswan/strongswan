/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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
 * @defgroup cga_trust cga_trust
 * @{ @ingroup cga_p
 */

#ifndef CGA_TRUST_H_
#define CGA_TRUST_H_

typedef struct cga_trust_t cga_trust_t;

#include <credentials/builder.h>
#include <credentials/certificates/certificate.h>

/**
 * IPv6 CGA trust anchor provider.
 */
struct cga_trust_t {

	/**
	 * Implements the credential_set_t
	 */
	credential_set_t set;

	/**
	 * Destroy credential set.
	 */
	void (*destroy)(cga_trust_t *this);
};

/**
 * Create a credential set providing a trust anchor for verified CGAs.
 *
 * @return			credential set
 */
cga_trust_t *cga_trust_create();

#endif /** CGA_TRUST_H_ @}*/
