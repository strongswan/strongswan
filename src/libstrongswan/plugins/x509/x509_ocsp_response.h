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
 * @defgroup x509_ocsp_response x509_ocsp_response
 * @{ @ingroup x509_p
 */

#ifndef X509_OCSP_RESPONSE_H_
#define X509_OCSP_RESPONSE_H_

#include <credentials/certificates/ocsp_response.h>

typedef struct x509_ocsp_response_t x509_ocsp_response_t;

/**
 * Implementation of ocsp_response_t using own ASN1 parser.
 */
struct x509_ocsp_response_t {

	/**
	 * Implements the ocsp_response_t interface
	 */
	ocsp_response_t interface;
};

/**
 * Create the building facility for OCSP responses.
 *
 * @param type		certificate type, CERT_X509_OCSP_RESPONSE only
 * @return			builder instance to build OCSP responses
 */
builder_t *x509_ocsp_response_builder(certificate_type_t type);

#endif /* X509_OCSP_RESPONSE_H_ @}*/
