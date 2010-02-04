/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup tlsgroup tls
 * @{ @ingroup eap_tls
 *
 * @defgroup tls tls
 * @{ @ingroup tls
 */

#ifndef TLS_H_
#define TLS_H_

typedef enum tls_version_t tls_version_t;
typedef enum tls_content_type_t tls_content_type_t;
typedef enum tls_handshake_type_t tls_handshake_type_t;
typedef enum tls_cipher_suite_t tls_cipher_suite_t;
typedef struct tls_t tls_t;

#include <library.h>

/**
 * TLS/SSL version numbers
 */
enum tls_version_t {
	SSL_2_0 = 0x0200,
	SSL_3_0 = 0x0300,
	TLS_1_0 = 0x0301,
	TLS_1_1 = 0x0302,
	TLS_1_2 = 0x0303,
};

/**
 * Enum names for tls_version_t
 */
extern enum_name_t *tls_version_names;

/**
 * TLS higher level content type
 */
enum tls_content_type_t {
	TLS_CHANGE_CIPHER_SPEC = 20,
	TLS_ALERT = 21,
	TLS_HANDSHAKE = 22,
	TLS_APPLICATION_DATA = 23,
};

/**
 * Enum names for tls_content_type_t
 */
extern enum_name_t *tls_content_type_names;

/**
 * TLS handshake subtype
 */
enum tls_handshake_type_t {
	TLS_HELLO_REQUEST = 0,
	TLS_CLIENT_HELLO = 1,
	TLS_SERVER_HELLO = 2,
	TLS_CERTIFICATE = 11,
	TLS_SERVER_KEY_EXCHANGE = 12,
	TLS_CERTIFICATE_REQUEST = 13,
	TLS_SERVER_HELLO_DONE = 14,
	TLS_CERTIFICATE_VERIFY = 15,
	TLS_CLIENT_KEY_EXCHANGE = 16,
	TLS_FINISHED = 20,
};

/**
 * Enum names for tls_handshake_type_t
 */
extern enum_name_t *tls_handshake_type_names;

enum tls_cipher_suite_t {
	TLS_NULL_WITH_NULL_NULL =				0x00,
	TLS_RSA_WITH_NULL_MD5 =					0x01,
	TLS_RSA_WITH_NULL_SHA =					0x02,
	TLS_RSA_WITH_NULL_SHA256 =				0x3B,
	TLS_RSA_WITH_RC4_128_MD5 =				0x04,
	TLS_RSA_WITH_RC4_128_SHA =				0x05,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA =			0x0A,
	TLS_RSA_WITH_AES_128_CBC_SHA =			0x2F,
	TLS_RSA_WITH_AES_256_CBC_SHA =			0x35,
	TLS_RSA_WITH_AES_128_CBC_SHA256 =		0x3C,
	TLS_RSA_WITH_AES_256_CBC_SHA256 =		0x3D,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA =		0x0D,
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA =		0x10,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA =		0x13,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA =		0x16,
	TLS_DH_DSS_WITH_AES_128_CBC_SHA =		0x30,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA =		0x31,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA =		0x32,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA =		0x33,
	TLS_DH_DSS_WITH_AES_256_CBC_SHA =		0x36,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA =		0x37,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA =		0x38,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA =		0x39,
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256 =	0x3E,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256 =	0x3F,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 =	0x40,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 =	0x67,
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256 =	0x68,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256 =	0x69,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 =	0x6A,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 =	0x6B,
	TLS_DH_ANON_WITH_RC4_128_MD5 =			0x18,
	TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA =		0x1B,
	TLS_DH_ANON_WITH_AES_128_CBC_SHA =		0x34,
	TLS_DH_ANON_WITH_AES_256_CBC_SHA =		0x3A,
	TLS_DH_ANON_WITH_AES_128_CBC_SHA256 =	0x6C,
	TLS_DH_ANON_WITH_AES_256_CBC_SHA256 =	0x6D,
};

/**
 * A bottom-up driven TLS stack, suitable for EAP implementations.
 */
struct tls_t {

	/**
	 * Process a TLS record, pass it to upper layers.
	 *
	 * @param type		type of the TLS record to process
	 * @param data		associated TLS record data
	 * @return
	 *					- SUCCESS if TLS negotiation complete
	 *					- FAILED if TLS handshake failed
	 *					- NEED_MORE if more invocations to process/build needed
	 */
	status_t (*process)(tls_t *this, tls_content_type_t type, chunk_t data);

	/**
	 * Query upper layer for TLS record, build protected record.
	 *
	 * @param type		type of the built TLS record
	 * @param data		allocated data of the built TLS record
	 * @return
	 *					- SUCCESS if TLS negotiation complete
	 *					- FAILED if TLS handshake failed
	 *					- NEED_MORE if upper layers have more records to send
	 *					- INVALID_STATE if more input records required
	 */
	status_t (*build)(tls_t *this, tls_content_type_t *type, chunk_t *data);

	/**
	 * Check if TLS stack is acting as a server.
	 *
	 * @return			TRUE if server, FALSE if peer
	 */
	bool (*is_server)(tls_t *this);

	/**
	 * Get the negotiated TLS/SSL version.
	 *
	 * @return			negotiated TLS version
	 */
	tls_version_t (*get_version)(tls_t *this);

	/**
	 * Set the negotiated TLS/SSL version.
	 *
	 * @param version	negotiated TLS version
	 */
	void (*set_version)(tls_t *this, tls_version_t version);

	/**
	 * Change used cipher, including encryption and integrity algorithms.
	 *
	 * @param inbound	TRUE to use cipher for inbound data, FALSE for outbound
	 * @param signer	new signer to use
	 * @param crypter	new crypter to use
	 * @param iv		initial IV for crypter
	 */
	void (*change_cipher)(tls_t *this, bool inbound, signer_t *signer,
						  crypter_t *crypter, chunk_t iv);

	/**
	 * Destroy a tls_t.
	 */
	void (*destroy)(tls_t *this);
};

/**
 * Create a tls instance.
 *
 * @param is_server		TRUE to act as server, FALSE for client
 * @param server		server identity
 * @param peer			peer identity
 * @return				TLS stack
 */
tls_t *tls_create(bool is_server, identification_t *server,
				  identification_t *peer);

#endif /** TLS_H_ @}*/
