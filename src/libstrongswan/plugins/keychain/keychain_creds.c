/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "keychain_creds.h"

#include <utils/debug.h>

#include <Security/Security.h>

typedef struct private_keychain_creds_t private_keychain_creds_t;

/**
 * Private data of an keychain_creds_t object.
 */
struct private_keychain_creds_t {

	/**
	 * Public keychain_creds_t interface.
	 */
	keychain_creds_t public;
};

/**
 * Enumerator for certificates
 */
typedef struct {
	/* implements enumerator_t */
	enumerator_t public;
	/* currently enumerating certificate */
	certificate_t *current;
	/* id to filter for */
	identification_t *id;
	/* certificate public key type we are looking for */
	key_type_t type;
	/* array of binary certificates to enumerate */
	CFArrayRef certs;
	/* current position in array */
	int i;
} cert_enumerator_t;

METHOD(enumerator_t, enumerate_certs, bool,
	cert_enumerator_t *this, certificate_t **out)
{
	DESTROY_IF(this->current);
	this->current = NULL;

	while (this->i < CFArrayGetCount(this->certs))
	{
		certificate_t *cert;
		public_key_t *key;
		CFDataRef data;
		chunk_t chunk;

		data = CFArrayGetValueAtIndex(this->certs, this->i++);
		if (data)
		{
			chunk = chunk_create((char*)CFDataGetBytePtr(data),
								 CFDataGetLength(data));
			cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
									  BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
			if (cert)
			{
				if (!this->id || cert->has_subject(cert, this->id))
				{
					key = cert->get_public_key(cert);
					if (key)
					{
						if (this->type == KEY_ANY ||
							this->type == key->get_type(key))
						{
							key->destroy(key);
							this->current = cert;
							*out = cert;
							return TRUE;
						}
						key->destroy(key);
					}
				}
				cert->destroy(cert);
			}
		}
	}
	return FALSE;
}

METHOD(enumerator_t, destroy_certs, void,
	cert_enumerator_t *this)
{
	DESTROY_IF(this->current);
	CFRelease(this->certs);
	free(this);
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_keychain_creds_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	cert_enumerator_t *enumerator;
	OSStatus status;
	CFDictionaryRef query;
	CFArrayRef result;
	const void* keys[] = {
		kSecReturnData,
		kSecMatchLimit,
		kSecClass,
		kSecAttrCanVerify,
		kSecMatchTrustedOnly,
	};
	const void* values[] = {
		kCFBooleanTrue,
		kSecMatchLimitAll,
		kSecClassCertificate,
		kCFBooleanTrue,
		trusted ? kCFBooleanTrue : kCFBooleanFalse,
	};

	if (cert == CERT_ANY || cert == CERT_X509)
	{
		query = CFDictionaryCreate(NULL, keys, values, countof(keys),
								   &kCFTypeDictionaryKeyCallBacks,
								   &kCFTypeDictionaryValueCallBacks);
		if (query)
		{
			status = SecItemCopyMatching(query, (CFTypeRef*)&result);
			CFRelease(query);
			if (status == errSecSuccess)
			{
				INIT(enumerator,
					.public = {
						.enumerate = (void*)_enumerate_certs,
						.destroy = _destroy_certs,
					},
					.certs = result,
					.id = id,
					.type = key,
				);
				return &enumerator->public;
			}
		}
	}
	return enumerator_create_empty();
}

METHOD(keychain_creds_t, destroy, void,
	private_keychain_creds_t *this)
{
	free(this);
}

/**
 * See header
 */
keychain_creds_t *keychain_creds_create()
{
	private_keychain_creds_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = (void*)enumerator_create_empty,
				.create_private_enumerator = (void*)enumerator_create_empty,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_cdp_enumerator  = (void*)enumerator_create_empty,
				.cache_cert = (void*)nop,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
