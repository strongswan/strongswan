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
 * @defgroup pem pem
 * @{ @ingroup containers
 */

#ifndef PEM_H_
#define PEM_H_

#include <credentials/containers/container.h>
#include <credentials/certificates/certificate.h>

typedef struct pem_t pem_t;
typedef enum pem_selection_t pem_selection_t;

/**
 * Selection mode for enumerating certificates in PEM certificate bundles
 */
enum pem_selection_t {
	/** Select all X.509 certificates contained in the bundle */
	PEM_SELECTION_ALL,
	/** Select all certificates except self-signed CA certificates */
	PEM_SELECTION_NO_ROOT,
	/** Select only self-signed CA certificates */
	PEM_SELECTION_ROOT,
	/** Select all CA certificates */
	PEM_SELECTION_CA,
	/** Select all non-self-signed (intermediate) CA certificates */
	PEM_SELECTION_IM,
	/** Select all end entity certificates */
	PEM_SELECTION_EE,
};

/**
 * PEM certificate bundle container type.
 */
struct pem_t {

	/**
	 * Implements container_t.
	 */
	container_t container;

	/**
	 * Create an enumerator over selected certificates.
	 *
	 * @param selector	certificate selection mode
	 * @return			enumerator over certificate_t
	 */
	enumerator_t *(*create_cert_enumerator)(pem_t *this,
											pem_selection_t selector);

	/**
	 * Return the first certificate that matches the given selector.
	 *
	 * @param selector	certificate selection mode
	 * @return			certificate reference or NULL if no match was found
	 */
	certificate_t *(*get_first)(pem_t *this, pem_selection_t selector);
};

#endif /** PEM_H_ @}*/
