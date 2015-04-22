/*
 * Copyright (C) 2015 Tobias Brunner
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

#include "redirect_manager.h"

#include <collections/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_redirect_manager_t private_redirect_manager_t;

/**
 * Private data
 */
struct private_redirect_manager_t {

	/**
	 * Public interface
	 */
	redirect_manager_t public;

	/**
	 * Registered providers
	 */
	linked_list_t *providers;

	/**
	 * Lock to access list of providers
	 */
	rwlock_t *lock;
};

METHOD(redirect_manager_t, add_provider, void,
	private_redirect_manager_t *this, redirect_provider_t *provider)
{
	this->lock->write_lock(this->lock);
	this->providers->insert_last(this->providers, provider);
	this->lock->unlock(this->lock);
}

METHOD(redirect_manager_t, remove_provider, void,
	private_redirect_manager_t *this, redirect_provider_t *provider)
{
	this->lock->write_lock(this->lock);
	this->providers->remove(this->providers, provider, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Determine whether a client should be redirected using the callback with the
 * given offset into the redirect_provider_t interface.
 */
static bool should_redirect(private_redirect_manager_t *this, ike_sa_t *ike_sa,
							identification_t **gateway, size_t offset)
{
	enumerator_t *enumerator;
	void *provider;
	bool redirect = FALSE;

	this->lock->read_lock(this->lock);
	enumerator = this->providers->create_enumerator(this->providers);
	while (enumerator->enumerate(enumerator, &provider))
	{
		bool (**method)(void*,ike_sa_t*,identification_t**) = provider + offset;
		if (*method && (*method)(provider, ike_sa, gateway))
		{
			switch (*gateway ? (*gateway)->get_type(*gateway) : 0)
			{
				case ID_IPV4_ADDR:
				case ID_IPV6_ADDR:
				case ID_FQDN:
					redirect = TRUE;
					break;
				default:
					DBG1(DBG_CFG, "redirect provider returned invalid gateway");
					DESTROY_IF(*gateway);
					continue;
			}
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return redirect;
}

METHOD(redirect_manager_t, redirect_on_init, bool,
	private_redirect_manager_t *this, ike_sa_t *ike_sa,
	identification_t **gateway)
{
	return should_redirect(this, ike_sa, gateway,
						   offsetof(redirect_provider_t, redirect_on_init));
}

METHOD(redirect_manager_t, redirect_on_auth, bool,
	private_redirect_manager_t *this, ike_sa_t *ike_sa,
	identification_t **gateway)
{
	return should_redirect(this, ike_sa, gateway,
						   offsetof(redirect_provider_t, redirect_on_auth));
}

METHOD(redirect_manager_t, destroy, void,
	private_redirect_manager_t *this)
{
	this->providers->destroy(this->providers);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * Described in header
 */
redirect_manager_t *redirect_manager_create()
{
	private_redirect_manager_t *this;

	INIT(this,
		.public = {
			.add_provider = _add_provider,
			.remove_provider = _remove_provider,
			.redirect_on_init = _redirect_on_init,
			.redirect_on_auth = _redirect_on_auth,
			.destroy = _destroy,
		},
		.providers = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
