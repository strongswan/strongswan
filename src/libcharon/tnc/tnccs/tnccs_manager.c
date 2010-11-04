/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnccs_manager.h"

#include <utils/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_tnccs_manager_t private_tnccs_manager_t;
typedef struct tnccs_entry_t tnccs_entry_t;

/**
 * TNCCS constructor entry
 */
struct tnccs_entry_t {

	/**
	 * TNCCS protocol type
	 */
	tnccs_type_t type;

	/**
	 * constructor function to create instance
	 */
	tnccs_constructor_t constructor;
};

/**
 * private data of tnccs_manager
 */
struct private_tnccs_manager_t {

	/**
	 * public functions
	 */
	tnccs_manager_t public;

	/**
	 * list of tnccs_entry_t's
	 */
	linked_list_t *protocols;

	/**
	 * rwlock to lock methods
	 */
	rwlock_t *lock;
};

METHOD(tnccs_manager_t, add_method, void,
	private_tnccs_manager_t *this, tnccs_type_t type,
	tnccs_constructor_t constructor)
{
	tnccs_entry_t *entry = malloc_thing(tnccs_entry_t);

	entry->type = type;
	entry->constructor = constructor;

	this->lock->write_lock(this->lock);
	this->protocols->insert_last(this->protocols, entry);
	this->lock->unlock(this->lock);
}

METHOD(tnccs_manager_t, remove_method, void,
	private_tnccs_manager_t *this, tnccs_constructor_t constructor)
{
	enumerator_t *enumerator;
	tnccs_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->protocols->create_enumerator(this->protocols);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (constructor == entry->constructor)
		{
			this->protocols->remove_at(this->protocols, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(tnccs_manager_t, create_instance, tnccs_t*,
	private_tnccs_manager_t *this, tnccs_type_t type, bool is_server)
{
	enumerator_t *enumerator;
	tnccs_entry_t *entry;
	tnccs_t *protocol = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->protocols->create_enumerator(this->protocols);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (type == entry->type)
		{
			protocol = entry->constructor(is_server);
			if (protocol)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return protocol;
}

METHOD(tnccs_manager_t, destroy, void,
	private_tnccs_manager_t *this)
{
	this->protocols->destroy_function(this->protocols, free);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * See header
 */
tnccs_manager_t *tnccs_manager_create()
{
	private_tnccs_manager_t *this;

	INIT(this,
			.public = {
				.add_method = _add_method,
				.remove_method = _remove_method,
				.create_instance = _create_instance,
				.destroy = _destroy,
			},
			.protocols = linked_list_create(),
			.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}

