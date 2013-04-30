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

/**
 * System Root certificates keychain
 */
#define SYSTEM_ROOTS "/System/Library/Keychains/SystemRootCertificates.keychain"

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

	/**
	 * System roots credential set
	 */
	mem_cred_t *roots;
};

/**
 * Load a credential set with System Root certificates
 */
static mem_cred_t* load_roots(private_keychain_creds_t *this)
{
	SecKeychainRef keychain;
	SecKeychainSearchRef search;
	SecKeychainItemRef item;
	mem_cred_t *set;
	OSStatus status;

	set = mem_cred_create();

	DBG1(DBG_CFG, "loading System Roots certificates:");
	status = SecKeychainOpen(SYSTEM_ROOTS, &keychain);
	if (status == errSecSuccess)
	{
		status = SecKeychainSearchCreateFromAttributes(keychain,
									kSecCertificateItemClass, NULL, &search);
		if (status == errSecSuccess)
		{
			while (SecKeychainSearchCopyNext(search, &item) == errSecSuccess)
			{
				certificate_t *cert;
				UInt32 len;
				void *data;

				if (SecKeychainItemCopyAttributesAndData(item, NULL, NULL, NULL,
												&len, &data) == errSecSuccess)
				{
					cert = lib->creds->create(lib->creds,
								CRED_CERTIFICATE, CERT_X509,
								BUILD_BLOB_ASN1_DER, chunk_create(data, len),
								BUILD_END);
					if (cert)
					{
						DBG1(DBG_CFG, "  loaded '%Y'", cert->get_subject(cert));
						set->add_cert(set, TRUE, cert);
					}
					SecKeychainItemFreeAttributesAndData(NULL, data);
				}
				CFRelease(item);
			}
			CFRelease(search);
		}
		CFRelease(keychain);
	}
	return set;
}

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
	lib->credmgr->remove_set(lib->credmgr, &this->roots->set);
	this->set->destroy(this->set);
	this->roots->destroy(this->roots);
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

	this->roots = load_roots(this);
	this->set = load_creds(this);

	lib->credmgr->add_set(lib->credmgr, &this->roots->set);
	lib->credmgr->add_set(lib->credmgr, &this->set->set);

	return &this->public;
}
