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

#include <collections/linked_list.h>
#include <utils/debug.h>

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

	/**
	 * IKE SA used for bus communication
	 */
	ike_sa_t *ike_sa;
};

/**
 * Free the memory allocated to a data entry
 */
static void free_entry(entry_t *this)
{
	this->method->destroy(this->method);
	this->ike_sa->destroy(this->ike_sa);
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
					   not ? "could not find" : op, (int)user_name.len,
					   user_name.ptr, (int)nas_id.len, nas_id.ptr);
	}
	else
	{
		DBG1(DBG_CFG, "%s RADIUS connection for user '%.*s'",
					   not ? "could not find" : op, (int)user_name.len,
					   user_name.ptr);
	}
}

METHOD(tnc_pdp_connections_t, add, void,
	private_tnc_pdp_connections_t *this, chunk_t nas_id, chunk_t user_name,
	identification_t *peer, eap_method_t *method)
{
	enumerator_t *enumerator;
	entry_t *entry;
	ike_sa_id_t *ike_sa_id;
	ike_sa_t *ike_sa;
	bool found = FALSE;

	ike_sa_id = ike_sa_id_create(IKEV2_MAJOR_VERSION, 0, 0, FALSE);
	ike_sa = ike_sa_create(ike_sa_id, FALSE, IKEV2);
	ike_sa_id->destroy(ike_sa_id);
	ike_sa->set_other_id(ike_sa, peer);

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (equals_entry(entry, nas_id, user_name))
		{
			found = TRUE;
			entry->method->destroy(entry->method);
			entry->ike_sa->destroy(entry->ike_sa);
			DBG1(DBG_CFG, "removed stale RADIUS connection");
			entry->method = method;
			entry->ike_sa = ike_sa;
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
		entry->ike_sa = ike_sa;
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

METHOD(tnc_pdp_connections_t, get_state, eap_method_t*,
	private_tnc_pdp_connections_t *this, chunk_t nas_id, chunk_t user_name,
	ike_sa_t **ike_sa)
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
			*ike_sa = entry->ike_sa;
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
			.get_state = _get_state,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
	);

	return &this->public;
}

