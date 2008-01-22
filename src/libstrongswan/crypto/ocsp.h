/**
 * @file ocsp.h
 * 
 * @brief Interface of ocsp_t
 * 
 */

/* Support of the Online Certificate Status Protocol (OCSP) Support
 *
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
 * Copyright (C) 2007 Andreas Steffen
 *
 * Hochschule fuer Technik Rapperswil, Switzerland
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
 * RCSID $Id$
 */

#ifndef OCSP_H_
#define OCSP_H_

typedef struct ocsp_t ocsp_t;

#include <credential_store.h>
#include <utils/linked_list.h>

#include "certinfo.h"

/* constants */
#define OCSP_BASIC_RESPONSE_VERSION	1
#define OCSP_DEFAULT_VALID_TIME		120  /* validity of one-time response in seconds */
#define OCSP_WARNING_INTERVAL		2    /* days */

/* OCSP response status */
typedef enum {
	STATUS_SUCCESSFUL =			0,
	STATUS_MALFORMEDREQUEST =	1,
	STATUS_INTERNALERROR =		2,
	STATUS_TRYLATER =			3,
	STATUS_SIGREQUIRED =		5,
	STATUS_UNAUTHORIZED=		6
} response_status;

/**
 * @brief Online Certficate Status Protocol (OCSP)
 *
 * @ingroup transforms
 */
struct ocsp_t {

	/**
	 * @brief Fetches the actual certificate status via OCSP
	 * 
	 * @param uris				linked list of ocsp uris
	 * @param certinfo			certificate status info to be updated
	 * @param credentials		credential store needed for trust path verification
	 */
	void (*fetch) (ocsp_t *this, certinfo_t *certinfo, credential_store_t *credentials);

	/**
	 * @brief Destroys the ocsp_t object.
	 * 
	 * @param this			ocsp object to destroy
	 */
	void (*destroy) (ocsp_t *this);

};

/**
 * @brief Create an ocsp_t object.
 * 
 * @param cacert 	ca certificate
 * @param uris	 	linked list of ocsp uris
 * @return 			created ocsp_t object
 * 
 * @ingroup transforms
 */
ocsp_t *ocsp_create(x509_t *cacert, linked_list_t *uris);

#endif /* OCSP_H_ */
