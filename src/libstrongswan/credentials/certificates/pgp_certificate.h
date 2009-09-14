/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup pgp_certificate pgp_certificate
 * @{ @ingroup certificates
 */

#ifndef PGP_CERTIFICATE_H_
#define PGP_CERTIFICATE_H_

#include <credentials/certificates/certificate.h>

typedef struct pgp_certificate_t pgp_certificate_t;

/**
 * PGP certificate interface.
 */
struct pgp_certificate_t {

	/**
	 * Implements certificate_t.
	 */
	certificate_t interface;
};

#endif /** PGP_CERTIFICATE_H_ @}*/
