/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 * @defgroup certreq_payload certreq_payload
 * @{ @ingroup payloads
 */

#ifndef CERTREQ_PAYLOAD_H_
#define CERTREQ_PAYLOAD_H_

typedef struct certreq_payload_t certreq_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/cert_payload.h>

/**
 * Length of a CERTREQ payload without the CERTREQ data in bytes.
 */
#define CERTREQ_PAYLOAD_HEADER_LENGTH 5

/**
 * Class representing an IKEv2 CERTREQ payload.
 *
 * The CERTREQ payload format is described in RFC section 3.7.
 */
struct certreq_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Create an enumerator over contained keyids.
	 *
	 * @return			enumerator over chunk_t's.
	 */
	enumerator_t* (*create_keyid_enumerator)(certreq_payload_t *this);

	/**
	 * Get the type of contained certificate keyids.
	 *
	 * @return			certificate keyid type
	 */
	certificate_type_t (*get_cert_type)(certreq_payload_t *this);

	/**
	 * Add a certificates keyid to the payload.
	 *
	 * @param keyid		keyid of the trusted certifcate
	 * @return
	 */
	void (*add_keyid)(certreq_payload_t *this, chunk_t keyid);

	/**
	 * Destroys an certreq_payload_t object.
	 */
	void (*destroy) (certreq_payload_t *this);
};

/**
 * Creates an empty certreq_payload_t object.
 *
 * @return 				certreq payload
 */
certreq_payload_t *certreq_payload_create(void);

/**
 * Creates an empty certreq_payload_t for a kind of certificates.
 *
 * @param type			type of the added keyids
 * @return 				certreq payload
 */
certreq_payload_t *certreq_payload_create_type(certificate_type_t type);

#endif /** CERTREQ_PAYLOAD_H_ @}*/
