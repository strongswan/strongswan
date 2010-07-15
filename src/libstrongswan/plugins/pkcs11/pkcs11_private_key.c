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

#include "pkcs11_private_key.h"

#include "pkcs11_library.h"
#include "pkcs11_manager.h"

#include <debug.h>
#include <threading/mutex.h>

typedef struct private_pkcs11_private_key_t private_pkcs11_private_key_t;

/**
 * Private data of an pkcs11_private_key_t object.
 */
struct private_pkcs11_private_key_t {

	/**
	 * Public pkcs11_private_key_t interface.
	 */
	pkcs11_private_key_t public;

	/**
	 * PKCS#11 module
	 */
	pkcs11_library_t *lib;

	/**
	 * Token session
	 */
	CK_SESSION_HANDLE session;

	/**
	 * Mutex to lock session
	 */
	mutex_t *mutex;

	/**
	 * Key object on the token
	 */
	CK_OBJECT_HANDLE object;

	/**
	 * Associated public key
	 */
	public_key_t *pubkey;

	/**
	 * References to this key
	 */
	refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
	private_pkcs11_private_key_t *this)
{
	return this->pubkey->get_type(this->pubkey);
}

METHOD(private_key_t, get_keysize, size_t,
	private_pkcs11_private_key_t *this)
{
	return this->pubkey->get_keysize(this->pubkey);
}

/**
 * Get the Cryptoki mechanism for a signature scheme
 */
static CK_MECHANISM_PTR scheme_to_mechanism(signature_scheme_t scheme)
{
	static struct {
		signature_scheme_t scheme;
		CK_MECHANISM mechanism;
	} mappings[] = {
		{SIGN_RSA_EMSA_PKCS1_NULL,		{CKM_RSA_PKCS,				NULL, 0}},
		{SIGN_RSA_EMSA_PKCS1_SHA1,		{CKM_SHA1_RSA_PKCS,			NULL, 0}},
		{SIGN_RSA_EMSA_PKCS1_SHA256,	{CKM_SHA256_RSA_PKCS,		NULL, 0}},
		{SIGN_RSA_EMSA_PKCS1_SHA384,	{CKM_SHA384_RSA_PKCS,		NULL, 0}},
		{SIGN_RSA_EMSA_PKCS1_SHA512,	{CKM_SHA512_RSA_PKCS,		NULL, 0}},
		{SIGN_RSA_EMSA_PKCS1_MD5,		{CKM_MD5_RSA_PKCS,			NULL, 0}},
	};
	int i;

	for (i = 0; i < countof(mappings); i++)
	{
		if (mappings[i].scheme == scheme)
		{
			return &mappings[i].mechanism;
		}
	}
	return NULL;
}

METHOD(private_key_t, sign, bool,
	private_pkcs11_private_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t *signature)
{
	CK_MECHANISM_PTR mechanism;
	CK_BYTE_PTR buf;
	CK_ULONG len;
	CK_RV rv;

	mechanism = scheme_to_mechanism(scheme);
	if (!mechanism)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	this->mutex->lock(this->mutex);
	rv = this->lib->f->C_SignInit(this->session, mechanism, this->object);
	if (rv != CKR_OK)
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_LIB, "C_SignInit() failed: %N", ck_rv_names, rv);
		return FALSE;
	}
	buf = malloc(get_keysize(this));
	rv = this->lib->f->C_Sign(this->session, data.ptr, data.len, buf, &len);
	this->mutex->unlock(this->mutex);
	if (rv != CKR_OK)
	{
		DBG1(DBG_LIB, "C_Sign() failed: %N", ck_rv_names, rv);
		free(buf);
		return FALSE;
	}
	*signature = chunk_create(buf, len);
	return TRUE;
}

METHOD(private_key_t, decrypt, bool,
	private_pkcs11_private_key_t *this, chunk_t crypto, chunk_t *plain)
{
	return FALSE;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_pkcs11_private_key_t *this)
{
	return this->pubkey->get_ref(this->pubkey);
}

METHOD(private_key_t, get_fingerprint, bool,
	private_pkcs11_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return this->pubkey->get_fingerprint(this->pubkey, type, fingerprint);
}

METHOD(private_key_t, get_encoding, bool,
	private_pkcs11_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	return FALSE;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_pkcs11_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_pkcs11_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		if (this->pubkey)
		{
			this->pubkey->destroy(this->pubkey);
		}
		this->mutex->destroy(this->mutex);
		this->lib->f->C_CloseSession(this->session);
		free(this);
	}
}

/**
 * Find the PKCS#11 library by its friendly name
 */
static pkcs11_library_t* find_lib(char *module)
{
	pkcs11_manager_t *manager;
	enumerator_t *enumerator;
	pkcs11_library_t *p11, *found = NULL;
	CK_SLOT_ID slot;

	manager = pkcs11_manager_get();
	if (!manager)
	{
		return NULL;
	}
	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &slot))
	{
		if (streq(module, p11->get_name(p11)))
		{
			found = p11;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Find the key on the token
 */
static bool find_key(private_pkcs11_private_key_t *this, chunk_t keyid)
{
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_ID, keyid.ptr, keyid.len},
	};
	CK_OBJECT_HANDLE object;
	CK_KEY_TYPE type;
	CK_ATTRIBUTE attr[] = {
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_MODULUS, NULL, 0},
		{CKA_PUBLIC_EXPONENT, NULL, 0},
	};
	enumerator_t *enumerator;
	chunk_t modulus, pubexp;

	enumerator = this->lib->create_object_enumerator(this->lib,
						this->session, tmpl, countof(tmpl), attr, countof(attr));
	if (enumerator->enumerate(enumerator, &object))
	{
		switch (type)
		{
			case CKK_RSA:
				if (attr[0].ulValueLen == -1 || attr[1].ulValueLen == -1)
				{
					DBG1(DBG_CFG, "reading modulus/exponent from PKCS#1 failed");
					break;
				}
				modulus = chunk_create(attr[1].pValue, attr[1].ulValueLen);
				pubexp = chunk_create(attr[2].pValue, attr[2].ulValueLen);
				this->pubkey = lib->creds->create(lib->creds, CRED_PUBLIC_KEY,
									KEY_RSA, BUILD_RSA_MODULUS, modulus,
									BUILD_RSA_PUB_EXP, pubexp, BUILD_END);
				if (!this->pubkey)
				{
					DBG1(DBG_CFG, "extracting public key from PKCS#11 RSA "
						 "private key failed");
				}
				this->object = object;
				break;
			default:
				DBG1(DBG_CFG, "PKCS#11 key type %d not supported", type);
				break;
		}
	}
	enumerator->destroy(enumerator);
	return this->pubkey != NULL;
}

/**
 * See header.
 */
pkcs11_private_key_t *pkcs11_private_key_connect(key_type_t type, va_list args)
{
	private_pkcs11_private_key_t *this;
	char *keyid = NULL, *pin = NULL, *module = NULL;
	int slot = -1;
	CK_RV rv;
	chunk_t chunk;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_PKCS11_KEYID:
				keyid = va_arg(args, char*);
				continue;
			case BUILD_PKCS11_PIN:
				pin = va_arg(args, char*);
				continue;
			case BUILD_PKCS11_SLOT:
				slot = va_arg(args, int);
				continue;
			case BUILD_PKCS11_MODULE:
				module = va_arg(args, char*);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (!keyid || !pin || !module || slot == -1)
	{	/* we currently require all parameters, TODO: search for pubkeys */
		return NULL;
	}

	INIT(this,
		.public.key = {
			.get_type = _get_type,
			.sign = _sign,
			.decrypt = _decrypt,
			.get_keysize = _get_keysize,
			.get_public_key = _get_public_key,
			.equals = private_key_equals,
			.belongs_to = private_key_belongs_to,
			.get_fingerprint = _get_fingerprint,
			.has_fingerprint = private_key_has_fingerprint,
			.get_encoding = _get_encoding,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.ref = 1,
	);

	this->lib = find_lib(module);
	if (!this->lib)
	{
		DBG1(DBG_CFG, "PKCS#11 module '%s' not found", module);
		free(this);
		return NULL;
	}

	rv = this->lib->f->C_OpenSession(slot, CKF_SERIAL_SESSION,
									 NULL, NULL, &this->session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "opening private key session on '%s':%d failed: %N",
			 module, slot, ck_rv_names, rv);
		free(this);
		return NULL;
	}

	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);

	rv = this->lib->f->C_Login(this->session, CKU_USER, pin, strlen(pin));
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "login to '%s':%d failed: %N",
			 module, slot, ck_rv_names, rv);
		destroy(this);
		return NULL;
	}

	chunk = chunk_from_hex(chunk_create(keyid, strlen(keyid)), NULL);
	if (!find_key(this, chunk))
	{
		free(chunk.ptr);
		destroy(this);
		return NULL;
	}
	free(chunk.ptr);

	return &this->public;
}
