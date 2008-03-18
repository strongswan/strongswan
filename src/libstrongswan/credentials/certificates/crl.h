/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2006 Andreas Steffen
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
 * @defgroup crl crl
 * @{ @ingroup certificates
 */

#ifndef CRL_H_
#define CRL_H_

typedef struct crl_t crl_t;
typedef enum crl_reason_t crl_reason_t;

#include <library.h>
#include <utils/linked_list.h>

/**
 * RFC 2459 CRL reason codes
 */
enum crl_reason_t {
    CRL_UNSPECIFIED 			= 0,
    CRL_KEY_COMPROMISE			= 1,
    CRL_CA_COMPROMISE			= 2,
    CRL_AFFILIATION_CHANGED		= 3,
    CRL_SUPERSEDED				= 4,
    CRL_CESSATION_OF_OPERATON	= 5,
    CRL_CERTIFICATE_HOLD		= 6,
    CRL_REMOVE_FROM_CRL			= 8,
};

/**
 * enum names for crl_reason_t
 */
extern enum_name_t *crl_reason_names;

/**
 * X509 certificate revocation list (CRL) interface definition.
 */
struct crl_t {

	/**
	 * Implements (parts of) the certificate_t interface
	 */
	certificate_t certificate;
	
	/**
	 * Get the CRL serial number.
	 *
	 * @return			chunk pointing to internal crlNumber
	 */
	chunk_t (*get_serial)(crl_t *this);
	
	/**
	 * Get the the authorityKeyIdentifier.
	 *
	 * @return			authKeyIdentifier as identification_t*
	 */
	identification_t* (*get_authKeyIdentifier)(crl_t *this);
	
	/**
	 * Create an enumerator over all revoked certificates.
	 *
	 * The enumerator takes 3 pointer arguments:
	 * chunk_t serial, time_t revocation_date, crl_reason_t reason
	 *
	 * @return			enumerator over revoked certificates.
	 */
	enumerator_t* (*create_enumerator)(crl_t *this);
	
};

#endif /* CRL_H_ @}*/
