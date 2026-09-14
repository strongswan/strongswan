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

typedef struct pem_t pem_t;

/**
 * PEM certificate bundle container type.
 */
struct pem_t {

	/**
	 * Implements container_t.
	 */
	container_t container;

	/**
	 * Create an enumerator over contained certificates.
	 *
	 * @return			enumerator over certificate_t
	 */
	enumerator_t *(*create_cert_enumerator)(pem_t *this);
};

#endif /** PEM_H_ @}*/
