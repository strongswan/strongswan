/*
 * Copyright (C) 2011 Tobias Brunner
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

#include "pkcs11_dh.h"

#include <debug.h>
#include <library.h>

#include "pkcs11_manager.h"

typedef struct private_pkcs11_dh_t private_pkcs11_dh_t;

/**
 * Private data of an pkcs11_dh_t object.
 */
struct private_pkcs11_dh_t {

	/**
	 * Public pkcs11_dh_t interface
	 */
	pkcs11_dh_t public;

	/**
	 * PKCS#11 library
	 */
	pkcs11_library_t *lib;

	/**
	 * Session handle for this objct
	 */
	CK_SESSION_HANDLE session;

	/**
	 * Diffie Hellman group number.
	 */
	u_int16_t group;

	/**
	 * Handle for own private value
	 */
	CK_OBJECT_HANDLE pri_key;

	/**
	 * Own public value
	 */
	chunk_t pub_key;

	/**
	 * Shared secret
	 */
	chunk_t secret;

};

/**
 * Retrieve a CKA_VALUE from a CK_OBJECT_HANDLE, memory gets allocated
 */
static bool get_cka_value(private_pkcs11_dh_t *this, CK_OBJECT_HANDLE obj,
						  chunk_t *value)
{
	CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
	CK_RV rv;
	rv = this->lib->f->C_GetAttributeValue(this->session, obj, &attr, 1);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetAttributeValue(NULL) error: %N", ck_rv_names, rv);
		return FALSE;
	}
	*value = chunk_alloc(attr.ulValueLen);
	attr.pValue = value->ptr;
	rv = this->lib->f->C_GetAttributeValue(this->session, obj, &attr, 1);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GetAttributeValue() error: %N", ck_rv_names, rv);
		chunk_free(value);
		return FALSE;
	}
	return TRUE;
}

METHOD(diffie_hellman_t, set_other_public_value, void,
	private_pkcs11_dh_t *this, chunk_t value)
{
	CK_ATTRIBUTE attr[] = {
	};
	CK_MECHANISM mech = {
		CKM_DH_PKCS_DERIVE,
		value.ptr,
		value.len,
	};
	CK_OBJECT_HANDLE secret;
	CK_RV rv;

	rv = this->lib->f->C_DeriveKey(this->session, &mech, this->pri_key,
								   attr, countof(attr), &secret);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_DeriveKey() error: %N", ck_rv_names, rv);
		return;
	}
	if (!get_cka_value(this, secret, &this->secret))
	{
		return;
	}
}

METHOD(diffie_hellman_t, get_my_public_value, void,
	private_pkcs11_dh_t *this, chunk_t *value)
{
	*value = chunk_clone(this->pub_key);
}

METHOD(diffie_hellman_t, get_shared_secret, status_t,
	private_pkcs11_dh_t *this, chunk_t *secret)
{
	if (!this->secret.ptr)
	{
		return FAILED;
	}
	*secret = chunk_clone(this->secret);
	return SUCCESS;
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_pkcs11_dh_t *this)
{
	return this->group;
}

METHOD(diffie_hellman_t, destroy, void,
	private_pkcs11_dh_t *this)
{
	this->lib->f->C_CloseSession(this->session);
	chunk_clear(&this->pub_key);
	chunk_clear(&this->secret);
	free(this);
}

/**
 * Generate DH key pair
 */
static bool generate_key_pair(private_pkcs11_dh_t *this, size_t exp_len,
							  chunk_t g, chunk_t p)
{
	CK_ULONG bits = exp_len * 8;
	CK_ATTRIBUTE pub_attr[] = {
		{ CKA_PRIME, p.ptr, p.len },
		{ CKA_BASE, g.ptr, g.len },
	};
	CK_ATTRIBUTE pri_attr[] = {
		{ CKA_VALUE_BITS, &bits, sizeof(bits) },
	};
	CK_MECHANISM mech = {
		CKM_DH_PKCS_KEY_PAIR_GEN,
		NULL,
		0,
	};
	CK_OBJECT_HANDLE pub_key;
	CK_RV rv;

	rv = this->lib->f->C_GenerateKeyPair(this->session, &mech, pub_attr,
							countof(pub_attr), pri_attr, countof(pri_attr),
							&pub_key, &this->pri_key);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "C_GenerateKeyPair() error: %N", ck_rv_names, rv);
		return FALSE;
	}

	if (!get_cka_value(this, pub_key, &this->pub_key))
	{
		return FALSE;
	}
	return TRUE;
}

/**
 * Find a token we can use for DH algorithm
 */
static pkcs11_library_t *find_token(CK_SESSION_HANDLE *session)
{
	enumerator_t *tokens, *mechs;
	pkcs11_manager_t *manager;
	pkcs11_library_t *current, *found = NULL;
	CK_MECHANISM_TYPE type;
	CK_SLOT_ID slot;

	manager = lib->get(lib, "pkcs11-manager");
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
			/* we assume CKM_DH_PKCS_DERIVE is supported too */
			if (type == CKM_DH_PKCS_KEY_PAIR_GEN)
			{
				if (current->f->C_OpenSession(slot, CKF_SERIAL_SESSION,
											  NULL, NULL, session) == CKR_OK)
				{
					found = current;
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

/*
 * Generic internal constructor
 */
pkcs11_dh_t *create_generic(diffie_hellman_group_t group, size_t exp_len,
							chunk_t g, chunk_t p)
{
	private_pkcs11_dh_t *this;

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
		.group = group,
	);

	this->lib = find_token(&this->session);
	if (!this->lib)
	{
		free(this);
		return NULL;
	}

	if (!generate_key_pair(this, exp_len, g, p))
	{
		free(this);
		return NULL;
	}
	return &this->public;
}


/*
 * Described in header.
 */
pkcs11_dh_t *pkcs11_dh_create(diffie_hellman_group_t group)
{

	diffie_hellman_params_t *params;

	params = diffie_hellman_get_params(group);
	if (!params)
	{
		return NULL;
	}
	return create_generic(group, params->exp_len,
						  params->generator, params->prime);
}

/*
 * Described in header.
 */
pkcs11_dh_t *pkcs11_dh_create_custom(diffie_hellman_group_t group,
									 chunk_t g, chunk_t p)
{
	if (group == MODP_CUSTOM)
	{
		return create_generic(group, p.len, g, p);
	}
	return NULL;
}
