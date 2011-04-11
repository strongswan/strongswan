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

#include "pkcs11_plugin.h"

#include <library.h>
#include <debug.h>
#include <utils/linked_list.h>
#include <threading/mutex.h>

#include "pkcs11_manager.h"
#include "pkcs11_creds.h"
#include "pkcs11_private_key.h"
#include "pkcs11_public_key.h"
#include "pkcs11_hasher.h"

typedef struct private_pkcs11_plugin_t private_pkcs11_plugin_t;

/**
 * private data of pkcs11_plugin
 */
struct private_pkcs11_plugin_t {

	/**
	 * public functions
	 */
	pkcs11_plugin_t public;

	/**
	 * PKCS#11 library/slot manager
	 */
	pkcs11_manager_t *manager;

	/**
	 * List of credential sets, pkcs11_creds_t
	 */
	linked_list_t *creds;

	/**
	 * mutex to lock list
	 */
	mutex_t *mutex;
};

/**
 * Token event callback function
 */
static void token_event_cb(private_pkcs11_plugin_t *this, pkcs11_library_t *p11,
						   CK_SLOT_ID slot, bool add)
{
	enumerator_t *enumerator;
	pkcs11_creds_t *creds, *found = NULL;;

	if (add)
	{
		creds = pkcs11_creds_create(p11, slot);
		if (creds)
		{
			this->mutex->lock(this->mutex);
			this->creds->insert_last(this->creds, creds);
			this->mutex->unlock(this->mutex);
			lib->credmgr->add_set(lib->credmgr, &creds->set);
		}
	}
	else
	{
		this->mutex->lock(this->mutex);
		enumerator = this->creds->create_enumerator(this->creds);
		while (enumerator->enumerate(enumerator, &creds))
		{
			if (creds->get_library(creds) == p11 &&
				creds->get_slot(creds) == slot)
			{
				found = creds;
				this->creds->remove_at(this->creds, enumerator);
				break;
			}
		}
		enumerator->destroy(enumerator);
		this->mutex->unlock(this->mutex);

		if (found)
		{
			lib->credmgr->remove_set(lib->credmgr, &found->set);
			found->destroy(found);
			/* flush the cache after a token is gone */
			lib->credmgr->flush_cache(lib->credmgr, CERT_X509);
		}
	}
}

METHOD(plugin_t, get_name, char*,
	private_pkcs11_plugin_t *this)
{
	return "pkcs11";
}

METHOD(plugin_t, destroy, void,
	private_pkcs11_plugin_t *this)
{
	pkcs11_creds_t *creds;

	lib->creds->remove_builder(lib->creds,
							(builder_function_t)pkcs11_private_key_connect);
	while (this->creds->remove_last(this->creds, (void**)&creds) == SUCCESS)
	{
		lib->credmgr->remove_set(lib->credmgr, &creds->set);
		creds->destroy(creds);
	}
	lib->crypto->remove_hasher(lib->crypto,
							(hasher_constructor_t)pkcs11_hasher_create);
	this->creds->destroy(this->creds);
	this->manager->destroy(this->manager);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
plugin_t *pkcs11_plugin_create()
{
	private_pkcs11_plugin_t *this;
	enumerator_t *enumerator;
	pkcs11_library_t *p11;
	CK_SLOT_ID slot;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.creds = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	this->manager = pkcs11_manager_create((void*)token_event_cb, this);

	if (lib->settings->get_bool(lib->settings,
							"libstrongswan.plugins.pkcs11.use_hasher", FALSE))
	{
		lib->crypto->add_hasher(lib->crypto, HASH_MD2, get_name(this),
					(hasher_constructor_t)pkcs11_hasher_create);
		lib->crypto->add_hasher(lib->crypto, HASH_MD5, get_name(this),
					(hasher_constructor_t)pkcs11_hasher_create);
		lib->crypto->add_hasher(lib->crypto, HASH_SHA1, get_name(this),
					(hasher_constructor_t)pkcs11_hasher_create);
		lib->crypto->add_hasher(lib->crypto, HASH_SHA256, get_name(this),
					(hasher_constructor_t)pkcs11_hasher_create);
		lib->crypto->add_hasher(lib->crypto, HASH_SHA384, get_name(this),
					(hasher_constructor_t)pkcs11_hasher_create);
		lib->crypto->add_hasher(lib->crypto, HASH_SHA512, get_name(this),
					(hasher_constructor_t)pkcs11_hasher_create);
	}

	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, FALSE,
							(builder_function_t)pkcs11_private_key_connect);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA, TRUE,
							(builder_function_t)pkcs11_public_key_load);

	enumerator = this->manager->create_token_enumerator(this->manager);
	while (enumerator->enumerate(enumerator, &p11, &slot))
	{
		token_event_cb(this, p11, slot, TRUE);
	}
	enumerator->destroy(enumerator);

	return &this->public.plugin;
}
