/*
 * Copyright (C) 2012 Andreas Steffen
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

#include "tnc_pdp_connections.h"

#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_tnc_pdp_connections_t private_tnc_pdp_connections_t;
typedef struct entry_t entry_t;

/**
 * Private data of tnc_pdp_connections_t
 */
struct private_tnc_pdp_connections_t {

	/**
	 * Implements tnc_pdp_connections_t interface
	 */
	tnc_pdp_connections_t public;

	/**
	 * List of TNC PEP RADIUS Connections
	 */ 
	linked_list_t *list;
};

/**
 * Data entry for a TNC PEP RADIUS connection
 */
struct entry_t {

	/**
	 * NAS identifier of PEP
	 */
	chunk_t nas_id;

	/**
	 * User name of TNC Client
	 */
	chunk_t user_name;

	/**
	 * EAP method state
	 */
	eap_method_t *method;
};

/**
 * Free the memory allocated to a data entry
 */
static void free_entry(entry_t *this)
{
	this->method->destroy(this->method);
	free(this->nas_id.ptr);
	free(this->user_name.ptr);
	free(this);
}

/**
 * Find a matching data entry
 */
static bool equals_entry( entry_t *this, chunk_t nas_id, chunk_t user_name)
{
	bool no_nas_id = !this->nas_id.ptr && !nas_id.ptr;

	return (chunk_equals(this->nas_id, nas_id) || no_nas_id) &&
			chunk_equals(this->user_name, user_name);
}

/**
 * Find a matching data entry
 */
static void dbg_nas_user(chunk_t nas_id, chunk_t user_name, bool not, char *op)
{
	if (nas_id.len)
	{
		DBG1(DBG_CFG, "%s RADIUS connection for user '%.*s' NAS '%.*s'",
			 		   not ? "could not find" : op, user_name.len, user_name.ptr,
					   nas_id.len, nas_id.ptr);
	}
	else
	{
		DBG1(DBG_CFG, "%s RADIUS connection for user '%.*s'", 
					   not ? "could not find" : op, user_name.len, user_name.ptr);
	}
}

METHOD(tnc_pdp_connections_t, add, void,
	private_tnc_pdp_connections_t *this, chunk_t nas_id, chunk_t user_name,
	eap_method_t *method)
{
	enumerator_t *enumerator;
	entry_t *entry;
	bool found = FALSE;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (equals_entry(entry, nas_id, user_name))
		{
			found = TRUE;
			entry->method->destroy(entry->method);
			DBG1(DBG_CFG, "removed stale TNC PEP RADIUS connection");
			entry->method = method;
			break;
		}
	}
	enumerator->destroy(enumerator);
	
	if (!found)
	{
		entry = malloc_thing(entry_t);
		entry->nas_id = chunk_clone(nas_id);
		entry->user_name = chunk_clone(user_name);
		entry->method = method;
		this->list->insert_last(this->list, entry);
	}
	dbg_nas_user(nas_id, user_name, FALSE, "created");
}

METHOD(tnc_pdp_connections_t, remove_, void,
	private_tnc_pdp_connections_t *this, chunk_t nas_id, chunk_t user_name)
{
	enumerator_t *enumerator;
	entry_t *entry;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (equals_entry(entry, nas_id, user_name))
		{
			free_entry(entry);
			this->list->remove_at(this->list, enumerator);
			dbg_nas_user(nas_id, user_name, FALSE, "removed");
			break;
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(tnc_pdp_connections_t, get_method, eap_method_t*,
	private_tnc_pdp_connections_t *this, chunk_t nas_id, chunk_t user_name)
{
	enumerator_t *enumerator;
	entry_t *entry;
	eap_method_t *found = NULL;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (equals_entry(entry, nas_id, user_name))
		{
			found = entry->method;
			break;
		}
	}
	enumerator->destroy(enumerator);

	dbg_nas_user(nas_id, user_name, !found, "found");
	return found;
}

METHOD(tnc_pdp_connections_t, destroy, void,
	private_tnc_pdp_connections_t *this)
{
	this->list->destroy_function(this->list, (void*)free_entry);
	free(this);
}

/*
 * see header file
 */
tnc_pdp_connections_t *tnc_pdp_connections_create(void)
{
	private_tnc_pdp_connections_t *this;

	INIT(this,
		.public = {
			.add = _add,
			.remove = _remove_,
			.get_method = _get_method,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
	);

	return &this->public;
}

