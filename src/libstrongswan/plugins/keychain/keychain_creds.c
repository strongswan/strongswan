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
#include <credentials/sets/mem_cred.h>

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

	/**
	 * Active in-memory credential set
	 */
	mem_cred_t *set;
};

/**
 * Create a credential set loaded with certificates
 */
static mem_cred_t* load_creds(private_keychain_creds_t *this)
{
	mem_cred_t *set;
	OSStatus status;
	CFDictionaryRef query;
	CFArrayRef certs;
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
		kCFBooleanTrue,
	};
	int i;

	set = mem_cred_create();

	DBG1(DBG_CFG, "loading System certificates:");
	query = CFDictionaryCreate(NULL, keys, values, countof(keys),
							   &kCFTypeDictionaryKeyCallBacks,
							   &kCFTypeDictionaryValueCallBacks);
	if (query)
	{
		status = SecItemCopyMatching(query, (CFTypeRef*)&certs);
		CFRelease(query);
		if (status == errSecSuccess)
		{
			for (i = 0; i < CFArrayGetCount(certs); i++)
			{
				certificate_t *cert;
				CFDataRef data;
				chunk_t chunk;

				data = CFArrayGetValueAtIndex(certs, i);
				if (data)
				{
					chunk = chunk_create((char*)CFDataGetBytePtr(data),
										 CFDataGetLength(data));
					cert = lib->creds->create(lib->creds,
										CRED_CERTIFICATE, CERT_X509,
										BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
					if (cert)
					{
						DBG1(DBG_CFG, "  loaded '%Y'", cert->get_subject(cert));
						set->add_cert(set, TRUE, cert);
					}
				}
			}
			CFRelease(certs);
		}
	}
	return set;
}

METHOD(keychain_creds_t, destroy, void,
	private_keychain_creds_t *this)
{
	lib->credmgr->remove_set(lib->credmgr, &this->set->set);
	this->set->destroy(this->set);
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
			.destroy = _destroy,
		},
	);

	this->set = load_creds(this);
	lib->credmgr->add_set(lib->credmgr, &this->set->set);

	return &this->public;
}
