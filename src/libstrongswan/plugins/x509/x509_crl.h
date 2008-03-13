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
 * @defgroup x509_crl x509_crl
 * @{ @ingroup x509_p
 */

#ifndef X509_CRL_H_
#define X509_CRL_H_

typedef struct x509_crl_t x509_crl_t;

#include <credentials/certificates/crl.h>

/**
 * Implementation of the X509 certification revocation list.
 */
struct x509_crl_t {

	/**
	 * Implements the crl_t interface
	 */
	crl_t crl;
};


/**
 * Create the building facility for x509 certificate revocation lists.
 *
 * @param type		certificate type, CERT_X509_CRL only
 * @return			builder instance to build certificate
 */
builder_t *x509_crl_builder(certificate_type_t type);

#endif /* X509_CRL_H_ @}*/
