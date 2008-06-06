/*
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "ike_cfg.h"

#include <string.h>


typedef struct private_ike_cfg_t private_ike_cfg_t;

/**
 * Private data of an ike_cfg_t object
 */
struct private_ike_cfg_t {

	/**
	 * Public part
	 */
	ike_cfg_t public;
	
	/**
	 * Number of references hold by others to this ike_cfg
	 */
	refcount_t refcount;

	/**
	 * Address of local host
	 */
	char *me;

	/**
	 * Address of remote host
	 */	
	char *other;
	
	/**
	 * should we send a certificate request?
	 */
	bool certreq;
	
	/**
	 * enforce UDP encapsulation
	 */
	bool force_encap;
	
	/**
	 * List of proposals to use
	 */
	linked_list_t *proposals;
};

/**
 * Implementation of ike_cfg_t.certreq.
 */
static bool send_certreq(private_ike_cfg_t *this)
{
	return this->certreq;
}
	
/**
 * Implementation of ike_cfg_t.force_encap.
 */
static bool force_encap_meth(private_ike_cfg_t *this)
{
	return this->force_encap;
}

/**
 * Implementation of ike_cfg_t.get_my_addr.
 */
static char *get_my_addr(private_ike_cfg_t *this)
{
	return this->me;
}

/**
 * Implementation of ike_cfg_t.get_other_addr.
 */
static char *get_other_addr(private_ike_cfg_t *this)
{
	return this->other;
}

/**
 * Implementation of ike_cfg_t.add_proposal.
 */
static void add_proposal(private_ike_cfg_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, proposal);
}

/**
 * Implementation of ike_cfg_t.get_proposals.
 */
static linked_list_t* get_proposals(private_ike_cfg_t *this)
{
	iterator_t *iterator;
	proposal_t *current;
	linked_list_t *proposals = linked_list_create();
	
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		current = current->clone(current);
		proposals->insert_last(proposals, (void*)current);
	}
	iterator->destroy(iterator);
	
	return proposals;
}
	
/**
 * Implementation of ike_cfg_t.select_proposal.
 */
static proposal_t *select_proposal(private_ike_cfg_t *this,
								   linked_list_t *proposals)
{
	iterator_t *stored_iter, *supplied_iter;
	proposal_t *stored, *supplied, *selected;
	
	stored_iter = this->proposals->create_iterator(this->proposals, TRUE);
	supplied_iter = proposals->create_iterator(proposals, TRUE);
	
	/* compare all stored proposals with all supplied. Stored ones are preferred.*/
	while (stored_iter->iterate(stored_iter, (void**)&stored))
	{
		supplied_iter->reset(supplied_iter);
		
		while (supplied_iter->iterate(supplied_iter, (void**)&supplied))
		{
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
 * Implementation of ike_cfg_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_ike_cfg_t *this)
{
	enumerator_t *enumerator;
	proposal_t *proposal;
	u_int16_t dh_group = MODP_NONE;
	
	enumerator = this->proposals->create_enumerator(this->proposals);
	while (enumerator->enumerate(enumerator, &proposal))
	{
		if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP, &dh_group, NULL))
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return dh_group;
}

/**
 * Implementation of ike_cfg_t.equals.
 */
static bool equals(private_ike_cfg_t *this, private_ike_cfg_t *other)
{
	enumerator_t *e1, *e2;
	proposal_t *p1, *p2;
	bool eq = TRUE;
	
	if (this == other)
	{
		return TRUE;
	}
	if (this->public.equals != other->public.equals)
	{
		return FALSE;
	}
	if (this->proposals->get_count(this->proposals) !=
		other->proposals->get_count(other->proposals))
	{
		return FALSE;
	}
	e1 = this->proposals->create_enumerator(this->proposals);
	e2 = this->proposals->create_enumerator(this->proposals);
	while (e1->enumerate(e1, &p1) && e2->enumerate(e2, &p2))
	{
		if (!p1->equals(p1, p2))
		{
			eq = FALSE;
			break;
		}
	}
	e1->destroy(e1);
	e2->destroy(e2);

	return (eq &&
		this->certreq == other->certreq &&
		this->force_encap == other->force_encap &&
		streq(this->me, other->me) &&
		streq(this->other, other->other));
}

/**
 * Implementation of ike_cfg_t.get_ref.
 */
static ike_cfg_t* get_ref(private_ike_cfg_t *this)
{
	ref_get(&this->refcount);
	return &this->public;
}

/**
 * Implementation of ike_cfg_t.destroy.
 */
static void destroy(private_ike_cfg_t *this)
{
	if (ref_put(&this->refcount))
	{
		this->proposals->destroy_offset(this->proposals,
										offsetof(proposal_t, destroy));
		free(this->me);
		free(this->other);
		free(this);
	}
}

/**
 * Described in header.
 */
ike_cfg_t *ike_cfg_create(bool certreq, bool force_encap,
						  char *me, char *other)
{
	private_ike_cfg_t *this = malloc_thing(private_ike_cfg_t);
	
	/* public functions */
	this->public.send_certreq = (bool(*)(ike_cfg_t*))send_certreq;
	this->public.force_encap = (bool (*) (ike_cfg_t *))force_encap_meth;
	this->public.get_my_addr = (char*(*)(ike_cfg_t*))get_my_addr;
	this->public.get_other_addr = (char*(*)(ike_cfg_t*))get_other_addr;
	this->public.add_proposal = (void(*)(ike_cfg_t*, proposal_t*)) add_proposal;
	this->public.get_proposals = (linked_list_t*(*)(ike_cfg_t*))get_proposals;
	this->public.select_proposal = (proposal_t*(*)(ike_cfg_t*,linked_list_t*))select_proposal;
	this->public.get_dh_group = (diffie_hellman_group_t(*)(ike_cfg_t*)) get_dh_group;
	this->public.equals = (bool(*)(ike_cfg_t*,ike_cfg_t*)) equals;
	this->public.get_ref = (ike_cfg_t*(*)(ike_cfg_t*))get_ref;
	this->public.destroy = (void(*)(ike_cfg_t*))destroy;
	
	/* private variables */
	this->refcount = 1;
	this->certreq = certreq;
	this->force_encap = force_encap;
	this->me = strdup(me);
	this->other = strdup(other);
	this->proposals = linked_list_create();
	
	return &this->public;
}
