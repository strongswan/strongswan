/**
 * @file connection.c
 *
 * @brief Implementation of connection_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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
 */

#include <string.h>

#include <config/connections/connection.h>

#include <utils/linked_list.h>
#include <utils/logger.h>

/** 
 * String mappings for cert_policy_t.
 */
mapping_t cert_policy_m[] = {
	{CERT_ALWAYS_SEND, "CERT_ALWAYS_SEND"},
	{CERT_SEND_IF_ASKED, "CERT_SEND_IF_ASKED"},
	{CERT_NEVER_SEND, "CERT_NEVER_SEND"},
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
	 * Number of references hold by others to this connection
	 */
	refcount_t refcount;

	/**
	 * Name of the connection
	 */
	char *name;
	
	/** 
	 * Does charon handle this connection? Or can he ignore it?
	 */
	bool ikev2;
	
	/**
	 * should we send a certificate request?
	 */
	cert_policy_t certreq_policy;
	
	/**
	 * should we send a certificates?
	 */
	cert_policy_t cert_policy;
	
	/**
	 * ID of us
	 */
	identification_t *my_id;

	/**
	 * Host information of my host.
	 */
	host_t *my_host;

	/**
	 * Host information of other host.
	 */	
	host_t *other_host;
	
	/**
	 * Interval to send DPD liveness checks on inactivity
	 */
	u_int32_t dpd_delay;
	
	/**
	 * Number of retransmission sequences to send bevore giving up
	 */
	u_int32_t retrans_sequences;
	
	/**
	 * Supported proposals
	 */
	linked_list_t *proposals;
	
	/**
	 * Time before an SA gets invalid
	 */
	u_int32_t soft_lifetime;
	
	/**
	 * Time before an SA gets rekeyed
	 */
	u_int32_t hard_lifetime;
	
	/**
	 * Time, which specifies the range of a random value
	 * substracted from soft_lifetime.
	 */
	u_int32_t jitter;
};

/**
 * Implementation of connection_t.get_name.
 */
static char *get_name (private_connection_t *this)
{
	return this->name;
}

/**
 * Implementation of connection_t.is_ikev2.
 */
static bool is_ikev2 (private_connection_t *this)
{
	return this->ikev2;
}

/**
 * Implementation of connection_t.get_certreq_policy.
 */
static cert_policy_t get_certreq_policy (private_connection_t *this)
{
	return this->certreq_policy;
}

/**
 * Implementation of connection_t.get_cert_policy.
 */
static cert_policy_t get_cert_policy (private_connection_t *this)
{
	return this->cert_policy;
}

/**
 * Implementation of connection_t.get_my_host.
 */
static host_t *get_my_host (private_connection_t *this)
{
	return this->my_host;
}

/**
 * Implementation of connection_t.get_other_host.
 */
static host_t *get_other_host (private_connection_t *this)
{
	return this->other_host;
}

/**
 * Implementation of connection_t.get_proposals.
 */
static linked_list_t* get_proposals(private_connection_t *this)
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
static void add_proposal(private_connection_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, proposal);
}

/**
 * Implementation of connection_t.get_dpd_delay.
 */
static u_int32_t get_dpd_delay(private_connection_t *this)
{
	return this->dpd_delay;
}

/**
 * Implementation of connection_t.get_retrans_seq.
 */
static u_int32_t get_retrans_seq(private_connection_t *this)
{
	return this->retrans_sequences;
}

/**
 * Implementation of connection_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_connection_t *this)
{
	iterator_t *iterator;
	proposal_t *proposal;
	algorithm_t *algo;
	diffie_hellman_group_t dh_group = MODP_NONE;
	
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP, &algo))
		{
			dh_group = algo->algorithm;
			break;
		}
	}
	iterator->destroy(iterator);
	return dh_group;
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
		alg_iter = proposal->create_algorithm_iterator(proposal, DIFFIE_HELLMAN_GROUP);
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
		alg_iter->destroy(alg_iter);
	}
	prop_iter->destroy(prop_iter);
	return FALSE;
}
/**
 * Implementation of connection_t.get_soft_lifetime
 */
static u_int32_t get_soft_lifetime(private_connection_t *this)
{
	if (this->jitter == 0)
	{
		return this->soft_lifetime ;
	}
	return this->soft_lifetime - (random() % this->jitter);
}

/**
 * Implementation of connection_t.get_hard_lifetime
 */
static u_int32_t get_hard_lifetime(private_connection_t *this)
{
	return this->hard_lifetime;
}

/**
 * Implementation of connection_t.get_ref.
 */
static void get_ref(private_connection_t *this)
{
	ref_get(&this->refcount);
}

/**
 * Implementation of connection_t.destroy.
 */
static void destroy(private_connection_t *this)
{
	if (ref_put(&this->refcount))
	{
		proposal_t *proposal;
		
		while (this->proposals->remove_last(this->proposals, (void**)&proposal) == SUCCESS)
		{
			proposal->destroy(proposal);
		}
		this->proposals->destroy(this->proposals);
		
		this->my_host->destroy(this->my_host);
		this->other_host->destroy(this->other_host);
		free(this->name);
		free(this);
	}
}

/**
 * Described in header.
 */
connection_t * connection_create(char *name, bool ikev2,
								 cert_policy_t cert_policy,
								 cert_policy_t certreq_policy,
								 host_t *my_host, host_t *other_host,
								 u_int32_t dpd_delay,
								 u_int32_t retrans_sequences,
								 u_int32_t hard_lifetime,
								 u_int32_t soft_lifetime, u_int32_t jitter)
{
	private_connection_t *this = malloc_thing(private_connection_t);
	
	/* public functions */
	this->public.get_name = (char*(*)(connection_t*))get_name;
	this->public.is_ikev2 = (bool(*)(connection_t*))is_ikev2;
	this->public.get_cert_policy = (cert_policy_t(*)(connection_t*))get_cert_policy;
	this->public.get_certreq_policy = (cert_policy_t(*)(connection_t*))get_certreq_policy;
	this->public.get_my_host = (host_t*(*)(connection_t*))get_my_host;
	this->public.get_other_host = (host_t*(*)(connection_t*))get_other_host;
	this->public.get_proposals = (linked_list_t*(*)(connection_t*))get_proposals;
	this->public.select_proposal = (proposal_t*(*)(connection_t*,linked_list_t*))select_proposal;
	this->public.add_proposal = (void(*)(connection_t*, proposal_t*)) add_proposal;
	this->public.get_dpd_delay = (u_int32_t(*)(connection_t*)) get_dpd_delay;
	this->public.get_retrans_seq = (u_int32_t(*)(connection_t*)) get_retrans_seq;
	this->public.get_dh_group = (diffie_hellman_group_t(*)(connection_t*)) get_dh_group;
	this->public.check_dh_group = (bool(*)(connection_t*,diffie_hellman_group_t)) check_dh_group;
	this->public.get_soft_lifetime = (u_int32_t (*) (connection_t *))get_soft_lifetime;
	this->public.get_hard_lifetime = (u_int32_t (*) (connection_t *))get_hard_lifetime;
	this->public.get_ref = (void(*)(connection_t*))get_ref;
	this->public.destroy = (void(*)(connection_t*))destroy;
	
	/* private variables */
	this->refcount = 1;
	this->name = strdup(name);
	this->ikev2 = ikev2;
	this->cert_policy = cert_policy;
	this->certreq_policy = certreq_policy;
	this->my_host = my_host;
	this->other_host = other_host;
	this->dpd_delay = dpd_delay;
	this->retrans_sequences = retrans_sequences;
	this->hard_lifetime = hard_lifetime;
	this->soft_lifetime = soft_lifetime;
	this->jitter = jitter;
	
	this->proposals = linked_list_create();
	
	return &this->public;
}
