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
 * @defgroup pubkey_cert pubkey_cert
 * @{ @ingroup certificates
 */

#ifndef PUBKEY_CERT_H_
#define PUBKEY_CERT_H_

#include <credentials/certificates/certificate.h>

typedef struct pubkey_cert_t pubkey_cert_t;

/**
 * A trusted public key wrapped into certificate of type CERT_TRUSTED_PUBKEY.
 */
struct pubkey_cert_t {

	/**
	 * Implements certificate_t.
	 */
	certificate_t interface;
};

/**
 * Create the builder for a trusted public key.
 *
 * The builders add() function takes BUILD_PUBLIC_KEY to enwrap.
 *
 * @param type		type of the certificate, must be CERT_pubkey_cert
 * @return 			builder instance
 */
builder_t *pubkey_cert_builder(certificate_type_t type);

#endif /** PUBKEY_CERT_H_ @}*/
