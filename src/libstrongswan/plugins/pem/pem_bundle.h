/*
 * Copyright (C) 2026 Tobias Brunner
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
 * @defgroup pem_bundle pem_bundle
 * @{ @ingroup pem_p
 */

#ifndef PEM_BUNDLE_H_
#define PEM_BUNDLE_H_

#include <credentials/certificates/certificate.h>
#include <credentials/containers/pem.h>

typedef struct pem_bundle_t pem_bundle_t;

/**
 * PEM certificate bundle container type.
 */
struct pem_bundle_t {

	/**
	 * Implements pem_t.
	 */
	pem_t pem;

	/**
	 * Add a certificate to the bundle.
	 *
	 * @param cert		certificate to add (adopted)
	 */
	void (*add_cert)(pem_bundle_t *this, certificate_t *cert);
};

/**
 * Create an empty PEM certificate bundle container.
 */
pem_bundle_t *pem_bundle_create();

#endif /** PEM_BUNDLE_H_ @}*/
