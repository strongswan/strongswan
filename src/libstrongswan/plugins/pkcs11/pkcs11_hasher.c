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

#include "pkcs11_hasher.h"

#include <unistd.h>

#include <debug.h>

#include "pkcs11_manager.h"

typedef struct private_pkcs11_hasher_t private_pkcs11_hasher_t;

/**
 * Private data of an pkcs11_hasher_t object.
 */
struct private_pkcs11_hasher_t {

	/**
	 * Public pkcs11_hasher_t interface.
	 */
	pkcs11_hasher_t public;

	/**
	 * PKCS#11 library
	 */
	pkcs11_library_t *lib;

	/**
	 * Mechanism for this hasher
	 */
	CK_MECHANISM_PTR mech;

	/**
	 * Token session
	 */
	CK_SESSION_HANDLE session;

	/**
	 * size of the hash
	 */
	size_t size;
};

METHOD(hasher_t, get_hash_size, size_t,
	private_pkcs11_hasher_t *this)
{
	return this->size;
}

/**
 * Try to handle errors
 */
static void handle_error(private_pkcs11_hasher_t *this, CK_RV rv)
{
	switch (rv)
	{
		case CKR_SESSION_CLOSED:
		case CKR_SESSION_HANDLE_INVALID:
		case CKR_USER_NOT_LOGGED_IN:
		case CKR_PIN_EXPIRED:
		case CKR_OPERATION_NOT_INITIALIZED:
			/* reopen session if we are in DigestInit? */
		case CKR_CRYPTOKI_NOT_INITIALIZED:
		case CKR_ARGUMENTS_BAD:
		case CKR_DEVICE_ERROR:
		case CKR_DEVICE_REMOVED:
		case CKR_GENERAL_ERROR:
		case CKR_MECHANISM_INVALID:
		case CKR_MECHANISM_PARAM_INVALID:
			DBG1(DBG_CFG, "PKCS#11 hasher fatal error: %N", ck_rv_names, rv);
			abort();
			break;
		case CKR_FUNCTION_CANCELED:
		case CKR_FUNCTION_FAILED:
		case CKR_OPERATION_ACTIVE:
		case CKR_HOST_MEMORY:
		case CKR_DEVICE_MEMORY:
			DBG1(DBG_CFG, "PKCS#11 hasher critical error: %N", ck_rv_names, rv);
			sleep(1);
			break;
	}
}

METHOD(hasher_t, reset, void,
	private_pkcs11_hasher_t *this)
{
	CK_RV rv;

	while ((rv = this->lib->f->C_DigestInit(this->session,
								this->mech)) != CKR_OK)
	{
		handle_error(this, rv);
	}
}

METHOD(hasher_t, get_hash, void,
	private_pkcs11_hasher_t *this, chunk_t chunk, u_int8_t *hash)
{
	CK_RV rv;
	CK_ULONG len;

	if (chunk.len)
	{
		while ((rv = this->lib->f->C_DigestUpdate(this->session,
									chunk.ptr, chunk.len)) != CKR_OK)
		{
			handle_error(this, rv);
		}
	}
	if (hash)
	{
		len = this->size;
		while ((rv = this->lib->f->C_DigestFinal(this->session,
								hash, &len)) != CKR_OK)
		{
			handle_error(this, rv);
		}
		reset(this);
	}
}

METHOD(hasher_t, allocate_hash, void,
	private_pkcs11_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(this->size);
		get_hash(this, chunk, hash->ptr);
	}
	else
	{
		get_hash(this, chunk, NULL);
	}
}

METHOD(hasher_t, destroy, void,
	private_pkcs11_hasher_t *this)
{
	this->lib->f->C_CloseSession(this->session);
	free(this);
}

/**
 * Get the Cryptoki mechanism for a hash algorithm
 */
static CK_MECHANISM_PTR algo_to_mechanism(hash_algorithm_t algo, size_t *size)
{
	static struct {
		hash_algorithm_t algo;
		CK_MECHANISM mechanism;
		size_t size;
	} mappings[] = {
		{HASH_MD2,		{CKM_MD2,		NULL, 0},	HASH_SIZE_MD2},
		{HASH_MD5,		{CKM_MD5,		NULL, 0},	HASH_SIZE_MD5},
		{HASH_SHA1,		{CKM_SHA_1,		NULL, 0},	HASH_SIZE_SHA1},
		{HASH_SHA256,	{CKM_SHA256,	NULL, 0},	HASH_SIZE_SHA256},
		{HASH_SHA384,	{CKM_SHA384,	NULL, 0},	HASH_SIZE_SHA384},
		{HASH_SHA512,	{CKM_SHA512,	NULL, 0},	HASH_SIZE_SHA512},
	};
	int i;

	for (i = 0; i < countof(mappings); i++)
	{
		if (mappings[i].algo == algo)
		{
			*size = mappings[i].size;
			return &mappings[i].mechanism;
		}
	}
	return NULL;
}

/**
 * Find a token we can use for a hash algorithm
 */
static pkcs11_library_t* find_token(hash_algorithm_t algo,
			CK_SESSION_HANDLE *session, CK_MECHANISM_PTR *mout, size_t *size)
{
	enumerator_t *tokens, *mechs;
	pkcs11_manager_t *manager;
	pkcs11_library_t *current, *found = NULL;
	CK_MECHANISM_TYPE type;
	CK_MECHANISM_PTR mech;
	CK_SLOT_ID slot;

	mech = algo_to_mechanism(algo, size);
	if (!mech)
	{
		return NULL;
	}
	manager = pkcs11_manager_get();
	if (!manager)
	{
		return NULL;
	}
	tokens = manager->create_token_enumerator(manager);
	while (tokens->enumerate(tokens, &current, &slot))
	{
		mechs = current->create_mechanism_enumerator(current, slot);
		while (mechs->enumerate(mechs, &type, NULL))
		{
			if (type == mech->mechanism)
			{
				if (current->f->C_OpenSession(slot, CKF_SERIAL_SESSION,
											  NULL, NULL, session) == CKR_OK)
				{
					found = current;
					*mout = mech;
					break;
				}
			}
		}
		mechs->destroy(mechs);
		if (found)
		{
			break;
		}
	}
	tokens->destroy(tokens);
	return found;
}

/**
 * See header
 */
pkcs11_hasher_t *pkcs11_hasher_create(hash_algorithm_t algo)
{
	private_pkcs11_hasher_t *this;
	CK_RV rv;

	INIT(this,
		.public.hasher = {
			.get_hash_size = _get_hash_size,
			.reset = _reset,
			.get_hash = _get_hash,
			.allocate_hash = _allocate_hash,
			.destroy = _destroy,
		},
	);

	this->lib = find_token(algo, &this->session, &this->mech, &this->size);
	if (!this->lib)
	{
		free(this);
		return NULL;
	}
	rv = this->lib->f->C_DigestInit(this->session, this->mech);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_DigestInit() failed: %N", ck_rv_names, rv);
		destroy(this);
		return NULL;
	}
	return &this->public;
}
