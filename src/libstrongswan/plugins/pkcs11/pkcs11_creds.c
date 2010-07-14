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

#include "pkcs11_creds.h"

#include <debug.h>
#include <utils/linked_list.h>

typedef struct private_pkcs11_creds_t private_pkcs11_creds_t;

/**
 * Private data of an pkcs11_creds_t object.
 */
struct private_pkcs11_creds_t {

	/**
	 * Public pkcs11_creds_t interface.
	 */
	pkcs11_creds_t public;

	/**
	 * PKCS# library
	 */
	pkcs11_library_t *lib;

	/**
	 * Token slot
	 */
	CK_SLOT_ID slot;

	/**
	 * List of trusted certificates
	 */
	linked_list_t *trusted;

	/**
	 * List of untrusted certificates
	 */
	linked_list_t *untrusted;
};

/**
 * Handle a certificate object, optionally trusted
 */
static void handle_certificate(private_pkcs11_creds_t *this,
							CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
							CK_BBOOL trusted)
{
	CK_ATTRIBUTE attrs[] = {
		{CKA_VALUE, NULL, 0},
		{CKA_LABEL, NULL, 0},
	};
	CK_RV rv;
	certificate_t *cert;

	rv = this->lib->f->C_GetAttributeValue(session, object,
										   attrs, countof(attrs));
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetAttributeValue(NULL) error: %N", ck_rv_names, rv);
		return;
	}
	if (attrs[0].ulValueLen)
	{
		attrs[0].pValue = malloc(attrs[0].ulValueLen);
	}
	if (attrs[1].ulValueLen)
	{
		attrs[1].pValue = malloc(attrs[1].ulValueLen);
	}
	rv = this->lib->f->C_GetAttributeValue(session, object,
										   attrs, countof(attrs));
	if (rv == CKR_OK)
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
				BUILD_BLOB_ASN1_DER,
				chunk_create(attrs[0].pValue, attrs[0].ulValueLen),
				BUILD_END);
		if (cert)
		{
			DBG1(DBG_CFG, "    loaded %strusted cert '%.*s'",
				 trusted ? "" : "un", attrs[1].ulValueLen, attrs[1].pValue);
			/* trusted certificates are also returned as untrusted */
			this->untrusted->insert_last(this->untrusted, cert);
			if (trusted)
			{
				this->trusted->insert_last(this->trusted, cert->get_ref(cert));
			}
		}
		else
		{
			DBG1(DBG_CFG, "    loading cert '%.*s' failed",
				 attrs[1].ulValueLen, attrs[1].pValue);
		}
	}
	else
	{
		DBG1(DBG_CFG, "C_GetAttributeValue() error: %N", ck_rv_names, rv);
	}
	free(attrs[0].pValue);
	free(attrs[1].pValue);
}

/**
 * Find certificates, optionally trusted
 */
static void find_certificates(private_pkcs11_creds_t *this,
							  CK_SESSION_HANDLE session, CK_BBOOL trusted)
{
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_CERTIFICATE_TYPE, &type, sizeof(type)},
		{CKA_TRUSTED, &trusted, sizeof(trusted)},
	};
	CK_OBJECT_HANDLE object;
	CK_ULONG found;
	CK_RV rv;

	rv = this->lib->f->C_FindObjectsInit(session, template, countof(template));
	if (rv == CKR_OK)
	{
		while (TRUE)
		{
			rv = this->lib->f->C_FindObjects(session, &object, 1, &found);
			if (rv == CKR_OK)
			{
				if (found == 1)
				{
					handle_certificate(this, session, object, trusted);
				}
				else
				{
					break;
				}
			}
			else
			{
				DBG1(DBG_CFG, "C_FindObjects() error: %N", ck_rv_names, rv);
				break;
			}
		}
	}
	this->lib->f->C_FindObjectsFinal(session);
}

/**
 * Load in the certificates from the token
 */
static bool load_certificates(private_pkcs11_creds_t *this)
{
	CK_SESSION_HANDLE session;
	CK_RV rv;

	rv = this->lib->f->C_OpenSession(this->slot, CKF_SERIAL_SESSION,
									 NULL, NULL, &session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "opening session failed: %N", ck_rv_names, rv);
		return FALSE;
	}

	find_certificates(this, session, CK_TRUE);
	find_certificates(this, session, CK_FALSE);

	this->lib->f->C_CloseSession(session);
	return TRUE;
}

/**
 * filter function for certs enumerator
 */
static bool certs_filter(identification_t *id,
						 certificate_t **in, certificate_t **out)
{
	public_key_t *public;
	certificate_t *cert = *in;

	if (id == NULL || cert->has_subject(cert, id))
	{
		*out = *in;
		return TRUE;
	}
	public = cert->get_public_key(cert);
	if (public)
	{
		if (public->has_fingerprint(public, id->get_encoding(id)))
		{
			public->destroy(public);
			*out = *in;
			return TRUE;
		}
		public->destroy(public);
	}
	return FALSE;
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_pkcs11_creds_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	enumerator_t *inner;

	if (cert != CERT_X509 && cert != CERT_ANY)
	{
		return NULL;
	}
	if (trusted)
	{
		inner = this->trusted->create_enumerator(this->trusted);
	}
	else
	{
		inner = this->untrusted->create_enumerator(this->untrusted);
	}
	return enumerator_create_filter(inner, (void*)certs_filter, id, NULL);
}

METHOD(pkcs11_creds_t, get_library, pkcs11_library_t*,
	private_pkcs11_creds_t *this)
{
	return this->lib;
}

METHOD(pkcs11_creds_t, get_slot, CK_SLOT_ID,
	private_pkcs11_creds_t *this)
{
	return this->slot;
}

METHOD(pkcs11_creds_t, destroy, void,
	private_pkcs11_creds_t *this)
{
	this->trusted->destroy_offset(this->trusted,
								offsetof(certificate_t, destroy));
	this->untrusted->destroy_offset(this->untrusted,
								offsetof(certificate_t, destroy));
	free(this);
}

/**
 * See header
 */
pkcs11_creds_t *pkcs11_creds_create(pkcs11_library_t *p11, CK_SLOT_ID slot)
{
	private_pkcs11_creds_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = (void*)enumerator_create_empty,
				.create_private_enumerator = (void*)enumerator_create_empty,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_cdp_enumerator  = (void*)enumerator_create_empty,
				.cache_cert = (void*)nop,
			},
			.get_library = _get_library,
			.get_slot = _get_slot,
			.destroy = _destroy,
		},
		.lib = p11,
		.slot = slot,
		.trusted = linked_list_create(),
		.untrusted = linked_list_create(),
	);

	if (!load_certificates(this))
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
