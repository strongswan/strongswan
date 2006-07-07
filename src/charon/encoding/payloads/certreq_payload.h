/**
 * @file certreq_payload.h
 * 
 * @brief Interface of certreq_payload_t.
 * 
 */

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

#ifndef CERTREQ_PAYLOAD_H_
#define CERTREQ_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/cert_payload.h>

/**
 * Length of a CERTREQ payload without the CERTREQ data in bytes.
 * 
 * @ingroup payloads
 */
#define CERTREQ_PAYLOAD_HEADER_LENGTH 5


typedef struct certreq_payload_t certreq_payload_t;

/**
 * @brief Class representing an IKEv2 CERTREQ payload.
 * 
 * The CERTREQ payload format is described in RFC section 3.7.
 * This is just a dummy implementation to fullfill the standards
 * requirements. A full implementation would offer setters/getters
 * for the different encoding types.
 * 
 * @b Constructors:
 * - certreq_payload_create()
 * 
 * @todo Implement payload functionality.
 * 
 * @ingroup payloads
 */
struct certreq_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the CERT encoding.
	 *
	 * @param this 			calling certreq_payload_t object
	 * @param encoding		CERT encoding
	 */
	void (*set_cert_encoding) (certreq_payload_t *this, cert_encoding_t encoding);
	
	/**
	 * @brief Get the CERT encoding.
	 *
	 * @param this 			calling certreq_payload_t object
	 * @return				Encoding of the CERT 
	 */
	cert_encoding_t (*get_cert_encoding) (certreq_payload_t *this);
	
	/**
	 * @brief Set the CERTREQ data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling certreq_payload_t object
	 * @param data			CERTREQ data as chunk_t
	 */
	void (*set_data) (certreq_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the CERTREQ data.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @param this 			calling certreq_payload_t object
	 * @return				CERTREQ data as chunk_t
	 */
	chunk_t (*get_data_clone) (certreq_payload_t *this);
	
	/**
	 * @brief Get the CERTREQ data.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling certreq_payload_t object
	 * @return				CERTREQ data as chunk_t
	 */
	chunk_t (*get_data) (certreq_payload_t *this);
	
	/**
	 * @brief Destroys an certreq_payload_t object.
	 *
	 * @param this 	certreq_payload_t object to destroy
	 */
	void (*destroy) (certreq_payload_t *this);
};

/**
 * @brief Creates an empty certreq_payload_t object.
 * 
 * @return certreq_payload_t object
 * 
 * @ingroup payloads
 */
certreq_payload_t *certreq_payload_create(void);


#endif /* CERTREQ_PAYLOAD_H_ */
