/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "eap_manager.h"

#include <utils/linked_list.h>
#include <utils/mutex.h>

typedef struct private_eap_manager_t private_eap_manager_t;
typedef struct eap_entry_t eap_entry_t;

/**
 * EAP constructor entry
 */
struct eap_entry_t {
	
	/**
	 * EAP method type, vendor specific if vendor is set
	 */
	eap_type_t type;
	
	/**
	 * vendor ID, 0 for default EAP methods
	 */
	u_int32_t vendor;
	
	/**
	 * Role of the method returned by the constructor, EAP_SERVER or EAP_PEER
	 */
	eap_role_t role;
	
	/**
	 * constructor function to create instance
	 */
	eap_constructor_t constructor;
};

/**
 * private data of eap_manager
 */
struct private_eap_manager_t {

	/**
	 * public functions
	 */
	eap_manager_t public;
	
	/**
	 * list of eap_entry_t's
	 */
	linked_list_t *methods;
	
	/**
	 * mutex to lock methods
	 */
	mutex_t *mutex;
};

/**
 * Implementation of eap_manager_t.add_method.
 */
static void add_method(private_eap_manager_t *this, eap_type_t type,
					   u_int32_t vendor, eap_role_t role,
					   eap_constructor_t constructor)
{
	eap_entry_t *entry = malloc_thing(eap_entry_t);
	
	entry->type = type;
	entry->vendor = vendor;
	entry->role = role;
	entry->constructor = constructor;

	this->mutex->lock(this->mutex);
	this->methods->insert_last(this->methods, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of eap_manager_t.remove_method.
 */
static void remove_method(private_eap_manager_t *this, eap_constructor_t constructor)
{
	enumerator_t *enumerator;
	eap_entry_t *entry;
	
	this->mutex->lock(this->mutex);
	enumerator = this->methods->create_enumerator(this->methods);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (constructor == entry->constructor)
		{
			this->methods->remove_at(this->methods, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of eap_manager_t.create_instance.
 */
static eap_method_t* create_instance(private_eap_manager_t *this,
									 eap_type_t type, u_int32_t vendor,
									 eap_role_t role, identification_t *server,
									 identification_t *peer)
{
	enumerator_t *enumerator;
	eap_entry_t *entry;
	eap_method_t *method = NULL;
	
	this->mutex->lock(this->mutex);
	enumerator = this->methods->create_enumerator(this->methods);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (type == entry->type && vendor == entry->vendor &&
			role == entry->role)
		{
			method = entry->constructor(server, peer);
			if (method)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return method;
}

/**
 * Implementation of 2008_t.destroy
 */
static void destroy(private_eap_manager_t *this)
{
	this->methods->destroy_function(this->methods, free);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
eap_manager_t *eap_manager_create()
{
	private_eap_manager_t *this = malloc_thing(private_eap_manager_t);
	
	this->public.add_method = (void(*)(eap_manager_t*, eap_type_t type, u_int32_t vendor, eap_role_t role, eap_constructor_t constructor))add_method;
	this->public.remove_method = (void(*)(eap_manager_t*, eap_constructor_t constructor))remove_method;
	this->public.create_instance = (eap_method_t*(*)(eap_manager_t*, eap_type_t type, u_int32_t vendor, eap_role_t role, identification_t*,identification_t*))create_instance;
	this->public.destroy = (void(*)(eap_manager_t*))destroy;
	
	this->methods = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	
	return &this->public;
}

