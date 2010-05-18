/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "xauth_manager.h"

typedef struct private_xauth_manager_t private_xauth_manager_t;

/**
 * private data of xauth_manager
 */
struct private_xauth_manager_t {

	/**
	 * public functions
	 */
	xauth_manager_t public;

	/**
	 * list of registered secret providers
	 */
	linked_list_t *providers;

	/**
	 * list of registered secret verifiers
	 */
	linked_list_t *verifiers;
};

METHOD(xauth_manager_t, get_secret, bool,
	private_xauth_manager_t *this, connection_t *c, chunk_t *secret)
{
	xauth_provider_t *provider;
	enumerator_t *enumerator;
 	bool success = FALSE;

	*secret = chunk_empty;

	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		if (provider->get_secret(provider, c, secret))
		{
			success = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return success;
}

METHOD(xauth_manager_t, verify_secret, bool,
	private_xauth_manager_t *this, connection_t *c, chunk_t secret)
{
	xauth_verifier_t *verifier;
	enumerator_t *enumerator;
	bool success = FALSE;

	enumerator = this->verifiers->create_enumerator(this->verifiers);
	while (enumerator->enumerate(enumerator, &verifier))
	{
		if (verifier->verify_secret(verifier, c, secret))
		{
			success = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return success;
}

METHOD(xauth_manager_t, add_provider, void,
	private_xauth_manager_t *this,	xauth_provider_t *provider)
{
	this->providers->insert_last(this->providers, provider);
}

METHOD(xauth_manager_t, add_verifier, void,
	private_xauth_manager_t *this,	xauth_verifier_t *verifier)
{
	this->verifiers->insert_last(this->verifiers, verifier);
}

METHOD(xauth_manager_t, destroy, void,
	private_xauth_manager_t *this)
{
	this->providers->destroy_offset(this->providers,
									offsetof(xauth_provider_t, destroy));
	this->verifiers->destroy_offset(this->verifiers,
									offsetof(xauth_verifier_t, destroy));
	free(this);
}

/*
 * Described in header.
 */
xauth_manager_t *xauth_manager_create()
{
	private_xauth_manager_t *this;

	INIT(this,
		.public = {
			.get_secret = _get_secret,
			.verify_secret = _verify_secret,
			.add_provider = _add_provider,
			.add_verifier = _add_verifier,
			.destroy = _destroy,
		 }
	);

	this->providers = linked_list_create();
	this->verifiers = linked_list_create();

	return &this->public;
}

