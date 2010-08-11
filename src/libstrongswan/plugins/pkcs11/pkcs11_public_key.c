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

#include "pkcs11_public_key.h"

#include "pkcs11.h"
#include "pkcs11_private_key.h"
#include "pkcs11_manager.h"

#include <debug.h>
#include <threading/mutex.h>

typedef struct private_pkcs11_public_key_t private_pkcs11_public_key_t;

/**
 * Private data of an pkcs11_public_key_t object.
 */
struct private_pkcs11_public_key_t {

	/**
	 * Public pkcs11_public_key_t interface.
	 */
	pkcs11_public_key_t public;

	/**
	 * Type of the key
	 */
	key_type_t type;

	/**
	 * Key size in bytes
	 */
	size_t k;

	/**
	 * PKCS#11 library this key uses
	 */
	pkcs11_library_t *lib;

	/**
	 * Slot the token is in
	 */
	CK_SLOT_ID slot;

	/**
	 * Session we use
	 */
	CK_SESSION_HANDLE session;

	/**
	 * Object handle to the key
	 */
	CK_OBJECT_HANDLE object;

	/**
	 * Mutex to lock session
	 */
	mutex_t *mutex;

	/**
	 * References to this key
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_pkcs11_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, get_keysize, int,
	private_pkcs11_public_key_t *this)
{
	return this->k * 8;
}

METHOD(public_key_t, verify, bool,
	private_pkcs11_public_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t sig)
{
	CK_MECHANISM_PTR mechanism;
	CK_RV rv;

	mechanism = pkcs11_signature_scheme_to_mech(scheme);
	if (!mechanism)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	if (sig.len && sig.ptr[0] == 0)
	{	/* trim leading zero byte in sig */
		sig = chunk_skip(sig, 1);
	}
	this->mutex->lock(this->mutex);
	rv = this->lib->f->C_VerifyInit(this->session, mechanism, this->object);
	if (rv != CKR_OK)
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_LIB, "C_VerifyInit() failed: %N", ck_rv_names, rv);
		return FALSE;
	}
	rv = this->lib->f->C_Verify(this->session, data.ptr, data.len,
								sig.ptr, sig.len);
	this->mutex->unlock(this->mutex);
	if (rv != CKR_OK)
	{
		DBG1(DBG_LIB, "C_Verify() failed: %N", ck_rv_names, rv);
		return FALSE;
	}
	return TRUE;
}

METHOD(public_key_t, encrypt, bool,
	private_pkcs11_public_key_t *this, encryption_scheme_t scheme,
	chunk_t plain, chunk_t *crypt)
{
	CK_MECHANISM_PTR mechanism;
	CK_BYTE_PTR buf;
	CK_ULONG len;
	CK_RV rv;

	mechanism = pkcs11_encryption_scheme_to_mech(scheme);
	if (!mechanism)
	{
		DBG1(DBG_LIB, "encryption scheme %N not supported",
			 encryption_scheme_names, scheme);
		return FALSE;
	}
	this->mutex->lock(this->mutex);
	rv = this->lib->f->C_EncryptInit(this->session, mechanism, this->object);
	if (rv != CKR_OK)
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_LIB, "C_EncryptInit() failed: %N", ck_rv_names, rv);
		return FALSE;
	}
	len = (get_keysize(this) + 7) / 8;
	buf = malloc(len);
	rv = this->lib->f->C_Encrypt(this->session, plain.ptr, plain.len, buf, &len);
	this->mutex->unlock(this->mutex);
	if (rv != CKR_OK)
	{
		DBG1(DBG_LIB, "C_Encrypt() failed: %N", ck_rv_names, rv);
		free(buf);
		return FALSE;
	}
	*crypt = chunk_create(buf, len);
	return TRUE;
}

/**
 * Encode RSA key using a given encoding type
 */
static bool encode_rsa(private_pkcs11_public_key_t *this,
					cred_encoding_type_t type, void *cache, chunk_t *encoding)
{
	CK_RV rv;
	bool success = FALSE;
	chunk_t n, e;
	CK_ATTRIBUTE attr[] = {
		{CKA_MODULUS, NULL, 0},
		{CKA_PUBLIC_EXPONENT, NULL, 0},
	};

	rv = this->lib->f->C_GetAttributeValue(this->session, this->object,
										   attr, countof(attr));
	if (rv != CKR_OK ||
		attr[0].ulValueLen == 0 || attr[0].ulValueLen == -1 ||
		attr[1].ulValueLen == 0 || attr[1].ulValueLen == -1)
	{
		return FALSE;
	}
	attr[0].pValue = malloc(attr[0].ulValueLen);
	attr[1].pValue = malloc(attr[1].ulValueLen);
	rv = this->lib->f->C_GetAttributeValue(this->session, this->object,
										   attr, countof(attr));
	if (rv == CKR_OK)
	{
		n = chunk_create(attr[0].pValue, attr[0].ulValueLen);
		e = chunk_create(attr[1].pValue, attr[1].ulValueLen);
		success = lib->encoding->encode(lib->encoding, type, cache, encoding,
			CRED_PART_RSA_MODULUS, n, CRED_PART_RSA_PUB_EXP, e, CRED_PART_END);
	}
	free(attr[0].pValue);
	free(attr[1].pValue);
	return success;
}

METHOD(public_key_t, get_encoding, bool,
	private_pkcs11_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (this->type)
	{
		case KEY_RSA:
			return encode_rsa(this, type, NULL, encoding);
		default:
			return FALSE;
	}
}

METHOD(public_key_t, get_fingerprint, bool,
	private_pkcs11_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	switch (this->type)
	{
		case KEY_RSA:
			return encode_rsa(this, type, this, fp);
		default:
			return FALSE;
	}
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_pkcs11_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_pkcs11_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		this->lib->f->C_CloseSession(this->session);
		this->mutex->destroy(this->mutex);
		free(this);
	}
}

/**
 * Create an empty PKCS#11 public key
 */
static private_pkcs11_public_key_t *create(key_type_t type, size_t k,
							pkcs11_library_t *p11, CK_SLOT_ID slot,
							CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	private_pkcs11_public_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.equals = public_key_equals,
				.get_keysize = _get_keysize,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.type = type,
		.k = k,
		.lib = p11,
		.slot = slot,
		.session = session,
		.object = object,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.ref = 1,
	);

	return this;
}

/**
 * Find a key object, including PKCS11 library and slot
 */
static private_pkcs11_public_key_t* find_rsa_key(chunk_t n, chunk_t e)
{
	private_pkcs11_public_key_t *this = NULL;
	pkcs11_manager_t *manager;
	enumerator_t *enumerator, *keys;
	pkcs11_library_t *p11;
	CK_SLOT_ID slot;

	manager = pkcs11_manager_get();
	if (!manager)
	{
		return NULL;
	}

	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &slot))
	{
		CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
		CK_KEY_TYPE type = CKK_RSA;
		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &class, sizeof(class)},
			{CKA_KEY_TYPE, &type, sizeof(type)},
			{CKA_MODULUS, n.ptr, n.len},
			{CKA_PUBLIC_EXPONENT, e.ptr, e.len},
		};
		CK_OBJECT_HANDLE object;
		CK_SESSION_HANDLE session;
		CK_RV rv;

		rv = p11->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
								   &session);
		if (rv != CKR_OK)
		{
			DBG1(DBG_CFG, "opening PKCS#11 session failed: %N", ck_rv_names, rv);
			continue;
		}
		keys = p11->create_object_enumerator(p11, session,
											 tmpl, countof(tmpl), NULL, 0);
		if (keys->enumerate(keys, &object))
		{
			this = create(KEY_RSA, n.len, p11, slot, session, object);
			keys->destroy(keys);
			break;
		}
		keys->destroy(keys);
		p11->f->C_CloseSession(session);
	}
	enumerator->destroy(enumerator);
	return this;
}

/**
 * Create a key object in a suitable token session
 */
static private_pkcs11_public_key_t* create_rsa_key(chunk_t n, chunk_t e)
{
	private_pkcs11_public_key_t *this = NULL;
	pkcs11_manager_t *manager;
	enumerator_t *enumerator, *mechs;
	pkcs11_library_t *p11;
	CK_SLOT_ID slot;

	manager = pkcs11_manager_get();
	if (!manager)
	{
		return NULL;
	}

	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &slot))
	{
		CK_MECHANISM_TYPE mech;
		CK_MECHANISM_INFO info;
		CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
		CK_KEY_TYPE type = CKK_RSA;
		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &class, sizeof(class)},
			{CKA_KEY_TYPE, &type, sizeof(type)},
			{CKA_MODULUS, n.ptr, n.len},
			{CKA_PUBLIC_EXPONENT, e.ptr, e.len}
		};
		CK_OBJECT_HANDLE object;
		CK_SESSION_HANDLE session;
		CK_RV rv;

		mechs = p11->create_mechanism_enumerator(p11, slot);
		while (mechs->enumerate(mechs, &mech, &info))
		{
			if (!(info.flags & CKF_VERIFY))
			{
				continue;
			}
			switch (mech)
			{
				case CKM_RSA_PKCS:
				case CKM_SHA1_RSA_PKCS:
				case CKM_SHA256_RSA_PKCS:
				case CKM_SHA384_RSA_PKCS:
				case CKM_SHA512_RSA_PKCS:
				case CKM_MD5_RSA_PKCS:
					break;
				default:
					continue;
			}
			rv = p11->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
									   &session);
			if (rv != CKR_OK)
			{
				DBG1(DBG_CFG, "opening PKCS#11 session failed: %N",
					 ck_rv_names, rv);
				continue;
			}
			rv = p11->f->C_CreateObject(session, tmpl, countof(tmpl), &object);
			if (rv == CKR_OK)
			{
				this = create(KEY_RSA, n.len, p11, slot, session, object);
				DBG2(DBG_CFG, "created RSA public key on token '%s':%d ",
					 p11->get_name(p11), slot);
				break;
			}
			else
			{
				DBG1(DBG_CFG, "creating RSA public key on token '%s':%d "
					 "failed: %N", p11->get_name(p11), slot, ck_rv_names, rv);
				p11->f->C_CloseSession(session);
			}
		}
		mechs->destroy(mechs);
		if (this)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return this;
}

/**
 * See header
 */
pkcs11_public_key_t *pkcs11_public_key_load(key_type_t type, va_list args)
{
	private_pkcs11_public_key_t *this;
	chunk_t n, e;

	n = e = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_RSA_MODULUS:
				n = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PUB_EXP:
				e = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (type == KEY_RSA && e.ptr && n.ptr)
	{
		if (n.len && n.ptr[0] == 0)
		{	/* trim leading zero byte in modulus */
			n = chunk_skip(n, 1);
		}
		this = find_rsa_key(n, e);
		if (this)
		{
			return &this->public;
		}
		this = create_rsa_key(n, e);
		if (this)
		{
			return &this->public;
		}
	}
	return NULL;
}

