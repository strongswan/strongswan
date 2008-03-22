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
 *
 * $Id$
 */

/**
 * @defgroup x509_cert x509_cert
 * @{ @ingroup x509_p
 */

#ifndef X509_CERT_H_
#define X509_CERT_H_

typedef struct x509_cert_t x509_cert_t;

#include <credentials/certificates/x509.h>

/**
 * Implementation of x509_t/certificate_t using own ASN1 parser.
 */
struct x509_cert_t {

	/**
	 * Implements the x509_t interface
	 */
	x509_t interface;
};

/**
 * Create the building facility for x509 certificates
 *
 * @param type		certificate type, CERT_X509 only
 * @return			builder instance to build certificate
 */
builder_t *x509_cert_builder(certificate_type_t type);

#endif /* X509_CERT_H_ @}*/
