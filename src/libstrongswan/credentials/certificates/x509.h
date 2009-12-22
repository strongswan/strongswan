/*
 * Copyright (C) 2007-2008 Martin Willi
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
 * @defgroup x509 x509
 * @{ @ingroup certificates
 */

#ifndef X509_H_
#define X509_H_

#include <utils/enumerator.h>
#include <credentials/certificates/certificate.h>

#define X509_NO_PATH_LEN_CONSTRAINT		-1
#define X509_MAX_PATH_LEN				 7

typedef struct x509_t x509_t;
typedef enum x509_flag_t x509_flag_t;

/**
 * X.509 certificate flags.
 */
enum x509_flag_t {
	/** cert has no constraints */
	X509_NONE =			0, 
	/** cert has CA constraint */
	X509_CA = 			(1<<0),
	/** cert has AA constraint */
	X509_AA = 			(1<<1),
	/** cert has OCSP signer constraint */
	X509_OCSP_SIGNER = 	(1<<2),
	/** cert has serverAuth constraint */
	X509_SERVER_AUTH = 	(1<<3),
	/** cert is self-signed */
	X509_SELF_SIGNED =  (1<<4),
};

/**
 * enum names for x509 flags
 */
extern enum_name_t *x509_flag_names;

/**
 * X.509 certificate interface.
 *
 * This interface adds additional methods to the certificate_t type to
 * allow further operations on these certificates.
 */
struct x509_t {

	/**
	 * Implements certificate_t.
	 */
	certificate_t interface;

	/**
	 * Get the flags set for this certificate.
	 *
	 * @return			set of flags
	 */
	x509_flag_t (*get_flags)(x509_t *this);

	/**
	 * Get the certificate serial number.
	 *
	 * @return			chunk pointing to internal serial number
	 */
	chunk_t (*get_serial)(x509_t *this);

	/**
	 * Get the the subjectKeyIdentifier.
	 *
	 * @return			subjectKeyIdentifier as chunk_t, internal data
	 */
	chunk_t (*get_subjectKeyIdentifier)(x509_t *this);

	/**
	 * Get the the authorityKeyIdentifier.
	 *
	 * @return			authKeyIdentifier as chunk_t, internal data
	 */
	chunk_t (*get_authKeyIdentifier)(x509_t *this);

	/**
	 * Get an optional path length constraint.
	 *
	 * @return			pathLenConstraint, -1 if no constraint exists
	 */
	int (*get_pathLenConstraint)(x509_t *this);

	/**
	 * Create an enumerator over all subjectAltNames.
	 *
	 * @return			enumerator over subjectAltNames as identification_t*
	 */
	enumerator_t* (*create_subjectAltName_enumerator)(x509_t *this);

	/**
	 * Create an enumerator over all CRL URIs.
	 *
	 * @return			enumerator over URIs as char*
	 */
	enumerator_t* (*create_crl_uri_enumerator)(x509_t *this);

	/**
	 * Create an enumerator over all OCSP URIs.
	 *
	 * @return			enumerator over URIs as char*
	 */
	enumerator_t* (*create_ocsp_uri_enumerator)(x509_t *this);

	/**
	 * Create an enumerator over all ipAddrBlocks.
	 *
	 * @return			enumerator over ipAddrBlocks as traffic_selector_t*
	 */
	enumerator_t* (*create_ipAddrBlock_enumerator)(x509_t *this);
};

#endif /** X509_H_ @}*/
