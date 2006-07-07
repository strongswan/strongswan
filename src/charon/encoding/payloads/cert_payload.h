/**
 * @file cert_payload.h
 * 
 * @brief Interface of cert_payload_t.
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

#ifndef CERT_PAYLOAD_H_
#define CERT_PAYLOAD_H_

#include <types.h>
#include <crypto/x509.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a cert payload without the cert data in bytes.
 * 
 * @ingroup payloads
 */
#define CERT_PAYLOAD_HEADER_LENGTH 5


typedef enum cert_encoding_t cert_encoding_t;

/**
 * @brief Certificate encoding, as described in IKEv2 RFC section 3.6
 * 
 * @ingroup payloads
 */
enum cert_encoding_t {
	CERT_NONE =						 0,
	CERT_PKCS7_WRAPPED_X509 =		 1,
	CERT_PGP =						 2,
	CERT_DNS_SIGNED_KEY =			 3,
	CERT_X509_SIGNATURE =			 4,
	CERT_KERBEROS_TOKEN	=			 6,
	CERT_CRL =						 7,
	CERT_ARL =						 8,
	CERT_SPKI =						 9,
	CERT_X509_ATTRIBUTE =			10,
	CERT_RAW_RSA_KEY =				11,
	CERT_X509_HASH_AND_URL =		12,
	CERT_X509_HASH_AND_URL_BUNDLE =	13
};

/**
 * string mappings for cert_encoding_t.
 * 
 * @ingroup payloads
 */
extern enum_names cert_encoding_names;

typedef struct cert_payload_t cert_payload_t;

/**
 * @brief Class representing an IKEv2 CERT payload.
 * 
 * The CERT payload format is described in RFC section 3.6.
 * This is just a dummy implementation to fullfill the standards
 * requirements. A full implementation would offer setters/getters
 * for the different encoding types.
 * 
 * @b Constructors:
 * - cert_payload_create()
 * 
 * @todo Implement setters/getters for the different certificate encodings.
 * 
 * @ingroup payloads
 */
struct cert_payload_t {
	
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the CERT encoding.
	 *
	 * @param this 			calling cert_payload_t object
	 * @param encoding		CERT encoding
	 */
	void (*set_cert_encoding) (cert_payload_t *this, cert_encoding_t encoding);
	
	/**
	 * @brief Get the CERT encoding.
	 *
	 * @param this 			calling cert_payload_t object
	 * @return				Encoding of the CERT 
	 */
	cert_encoding_t (*get_cert_encoding) (cert_payload_t *this);
	
	/**
	 * @brief Set the CERT data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling cert_payload_t object
	 * @param data			CERT data as chunk_t
	 */
	void (*set_data) (cert_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the CERT data.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @param this 			calling cert_payload_t object
	 * @return				CERT data as chunk_t
	 */
	chunk_t (*get_data_clone) (cert_payload_t *this);
	
	/**
	 * @brief Get the CERT data.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling cert_payload_t object
	 * @return				CERT data as chunk_t
	 */
	chunk_t (*get_data) (cert_payload_t *this);
	
	/**
	 * @brief Destroys an cert_payload_t object.
	 *
	 * @param this 			cert_payload_t object to destroy
	 */
	void (*destroy) (cert_payload_t *this);
};

/**
 * @brief Creates an empty cert_payload_t object.
 * 
 * @return					cert_payload_t object
 * 
 * @ingroup payloads
 */
cert_payload_t *cert_payload_create(void);

/**
 * @brief Creates a cert_payload_t object with an X.509 certificate.
 * 
 * @param cert				X.509 certificate
 * @return					cert_payload_t object
 * 
 * @ingroup payloads
 */
cert_payload_t *cert_payload_create_from_x509(x509_t *cert);

#endif /* CERT_PAYLOAD_H_ */
