/*
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2002-2008 Andreas Steffen
 *
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
 * @defgroup x509_ac x509_ac
 * @{ @ingroup x509_p
 */

#ifndef X509_AC_H_
#define X509_AC_H_

#include <credentials/certificates/ac.h>

typedef struct x509_ac_t x509_ac_t;

/**
 * Implementation of ocsp_request_t using own ASN1 parser.
 */
struct x509_ac_t {

	/**
	 * Implements the ac_t interface
	 */
	ac_t interface;
};

/**
 * Create the building facility for X.509 attribute certificates.
 *
 * The resulting builder accepts:
 * 	BUILD_USER_CERT: 	user certificate, exactly one
 *	BUILD_SIGNER_CERT:	signer certificate, exactly one
 *	BUILD_SIGNER_KEY:	signer private key, exactly one
 *  BUILD_SERIAL:		serial number, exactly one
 *  BUILD_GROUP_ATTR:	group attribute, optional, several possible
 *
 * @param type		certificate type, CERT_X509_AC only
 * @return			builder instance to build X.509 attribute certificates
 */
builder_t *x509_ac_builder(certificate_type_t type);

#endif /* X509_AC_H_ @}*/
