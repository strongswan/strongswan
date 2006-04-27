/**
 * @file connection.c
 * 
 * @brief Implementation of connection_t.
 *  
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <string.h>

#include "connection.h"

#include <utils/linked_list.h>
#include <utils/logger.h>

/** 
 * String mappings for auth_method_t.
 */
mapping_t auth_method_m[] = {
	{RSA_DIGITAL_SIGNATURE, "RSA"},
	{SHARED_KEY_MESSAGE_INTEGRITY_CODE, "SHARED_KEY"},
	{DSS_DIGITAL_SIGNATURE, "DSS"},
	{MAPPING_END, NULL}
};


typedef struct private_connection_t private_connection_t;

/**
 * Private data of an connection_t object
 */
struct private_connection_t {

	/**
	 * Public part
	 */
	connection_t public;

	/**
	 * Name of the connection
	 */
	char *name;
	
	/**
	 * ID of us
	 */
	identification_t *my_id;

	/**
	 * ID of remote peer
	 */	
	identification_t *other_id;

	/**
	 * Host information of my host.
	 */
	host_t *my_host;

	/**
	 * Host information of other host.
	 */	
	host_t *other_host;
	
	/**
	 * Method to use for own authentication data
	 */
	auth_method_t auth_method;
	
	/**
	 * Supported proposals
	 */
	linked_list_t *proposals;
};

/**
 * Implementation of connection_t.get_name.
 */
static char *get_name (private_connection_t *this)
{
	return this->name;
}

/**
 * Implementation of connection_t.get_my_id.
 */
static identification_t *get_my_id (private_connection_t *this)
{
	return this->my_id;
}

/**
 * Implementation of connection_t.get_other_id.
 */
static identification_t *get_other_id(private_connection_t *this)
{
	return this->other_id;
}

/**
 * Implementation of connection_t.get_my_host.
 */
static host_t * get_my_host (private_connection_t *this)
{
	return this->my_host;
}

/**
 * Implementation of connection_t.update_my_host.
 */
static void update_my_host(private_connection_t *this, host_t *my_host)
{
	this->my_host->destroy(this->my_host);
	this->my_host = my_host;
}

/**
 * Implementation of connection_t.update_other_host.
 */
static void update_other_host(private_connection_t *this, host_t *other_host)
{
	this->other_host->destroy(this->other_host);
	this->other_host = other_host;
}

/**
 * Implementation of connection_t.get_other_host.
 */
static host_t * get_other_host (private_connection_t *this)
{
	return this->other_host;
}

/**
 * Implementation of connection_t.get_proposals.
 */
static linked_list_t* get_proposals (private_connection_t *this)
{
	return this->proposals;
}
	
/**
 * Implementation of connection_t.select_proposal.
 */
static proposal_t *select_proposal(private_connection_t *this, linked_list_t *proposals)
{
	iterator_t *stored_iter, *supplied_iter;
	proposal_t *stored, *supplied, *selected;
	
	stored_iter = this->proposals->create_iterator(this->proposals, TRUE);
	supplied_iter = proposals->create_iterator(proposals, TRUE);
	
	/* compare all stored proposals with all supplied. Stored ones are preferred. */
	while (stored_iter->has_next(stored_iter))
	{
		supplied_iter->reset(supplied_iter);
		stored_iter->current(stored_iter, (void**)&stored);

		while (supplied_iter->has_next(supplied_iter))
		{
			supplied_iter->current(supplied_iter, (void**)&supplied);
			selected = stored->select(stored, supplied);
			if (selected)
			{
				/* they match, return */
				stored_iter->destroy(stored_iter);
				supplied_iter->destroy(supplied_iter);
				return selected;
			}
		}
	}
	
	/* no proposal match :-(, will result in a NO_PROPOSAL_CHOSEN... */
	stored_iter->destroy(stored_iter);
	supplied_iter->destroy(supplied_iter);
	
	return NULL;
}

/**
 * Implementation of connection_t.add_proposal.
 */
static void add_proposal (private_connection_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, proposal);
}

/**
 * Implementation of connection_t.auth_method_t.
 */
static auth_method_t get_auth_method(private_connection_t *this)
{
	return this->auth_method;
}

/**
 * Implementation of connection_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_connection_t *this)
{
	iterator_t *iterator;
	proposal_t *proposal;
	algorithm_t *algo;
	
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		proposal->get_algorithm(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP, &algo);
		if (algo)
		{
			iterator->destroy(iterator);
			return algo->algorithm;
		}
	}
	iterator->destroy(iterator);
	return MODP_UNDEFINED;
}

/**
 * Implementation of connection_t.check_dh_group.
 */
static bool check_dh_group(private_connection_t *this, diffie_hellman_group_t dh_group)
{
	iterator_t *prop_iter, *alg_iter;
	proposal_t *proposal;
	algorithm_t *algo;
	
	prop_iter = this->proposals->create_iterator(this->proposals, TRUE);
	while (prop_iter->has_next(prop_iter))
	{
		prop_iter->current(prop_iter, (void**)&proposal);
		alg_iter = proposal->create_algorithm_iterator(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP);
		while (alg_iter->has_next(alg_iter))
		{
			alg_iter->current(alg_iter, (void**)&algo);
			if (algo->algorithm == dh_group)
			{
				prop_iter->destroy(prop_iter);
				alg_iter->destroy(alg_iter);
				return TRUE;
			}
		}
	}
	prop_iter->destroy(prop_iter);
	alg_iter->destroy(alg_iter);
	return FALSE;
}

/**
 * Implementation of connection_t.clone.
 */
static connection_t *clone(private_connection_t *this)
{
	iterator_t *iterator;
	proposal_t *proposal;
	private_connection_t *clone = (private_connection_t*)connection_create(
			this->name,
			this->my_host->clone(this->my_host),
			this->other_host->clone(this->other_host),
			this->my_id->clone(this->my_id),
			this->other_id->clone(this->other_id),
			this->auth_method);
	
	/* clone all proposals */
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		proposal = proposal->clone(proposal);
		clone->proposals->insert_last(clone->proposals, (void*)proposal);
	}
	iterator->destroy(iterator);
	
	return &clone->public;
}

/**
 * Implementation of connection_t.destroy.
 */
static void destroy (private_connection_t *this)
{
	proposal_t *proposal;
	
	while (this->proposals->remove_last(this->proposals, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	this->proposals->destroy(this->proposals);
	
	this->my_host->destroy(this->my_host);
	this->other_host->destroy(this->other_host);
	this->my_id->destroy(this->my_id);
	this->other_id->destroy(this->other_id);
	free(this);
}

/**
 * Described in header.
 */
connection_t * connection_create(char *name, host_t *my_host, host_t *other_host, identification_t *my_id, identification_t *other_id, auth_method_t auth_method)
{
	private_connection_t *this = malloc_thing(private_connection_t);

	/* public functions */
	this->public.get_name = (char*(*)(connection_t*))get_name;
	this->public.get_my_id = (identification_t*(*)(connection_t*))get_my_id;
	this->public.get_other_id = (identification_t*(*)(connection_t*))get_other_id;
	this->public.get_my_host = (host_t*(*)(connection_t*))get_my_host;
	this->public.update_my_host = (void(*)(connection_t*,host_t*))update_my_host;
	this->public.update_other_host = (void(*)(connection_t*,host_t*))update_other_host;
	this->public.get_other_host = (host_t*(*)(connection_t*))get_other_host;
	this->public.get_proposals = (linked_list_t*(*)(connection_t*))get_proposals;
	this->public.select_proposal = (proposal_t*(*)(connection_t*,linked_list_t*))select_proposal;
	this->public.add_proposal = (void(*)(connection_t*, proposal_t*)) add_proposal;
	this->public.get_auth_method = (auth_method_t(*)(connection_t*)) get_auth_method;
	this->public.get_dh_group = (diffie_hellman_group_t(*)(connection_t*)) get_dh_group;
	this->public.check_dh_group = (bool(*)(connection_t*,diffie_hellman_group_t)) check_dh_group;
	this->public.clone = (connection_t*(*)(connection_t*))clone;
	this->public.destroy = (void(*)(connection_t*))destroy;
	
	/* private variables */
	this->name = strdup(name);
	this->my_host = my_host;
	this->other_host = other_host;
	this->my_id = my_id;
	this->other_id = other_id;
	this->auth_method = auth_method;
		
	this->proposals = linked_list_create();

	return (&this->public);
}
