/*
 * Copyright (C) 2007 Martin Willi
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

#include "backend_manager.h"

#include <sys/types.h>
#include <pthread.h>

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/mutex.h>


typedef struct private_backend_manager_t private_backend_manager_t;

/**
 * Private data of an backend_manager_t object.
 */
struct private_backend_manager_t {

	/**
	 * Public part of backend_manager_t object.
	 */
	backend_manager_t public;
	
	/**
	 * list of registered backends
	 */
	linked_list_t *backends;
	
	/**
	 * rwlock for backends
	 */
	rwlock_t *lock;
};

/**
 * match of an ike_cfg
 */
typedef enum ike_cfg_match_t {
	MATCH_NONE  = 0x00,
	MATCH_ANY   = 0x01,
	MATCH_ME    = 0x04,
	MATCH_OTHER = 0x08,
} ike_cfg_match_t;

/**
 * data to pass nested IKE enumerator
 */
typedef struct {
	private_backend_manager_t *this;
	host_t *me;
	host_t *other;
} ike_data_t;

/**
 * data to pass nested peer enumerator
 */
typedef struct {
	private_backend_manager_t *this;
	identification_t *me;
	identification_t *other;
} peer_data_t;

/**
 * inner enumerator constructor for IKE cfgs
 */
static enumerator_t *ike_enum_create(backend_t *backend, ike_data_t *data)
{
	return backend->create_ike_cfg_enumerator(backend, data->me, data->other);
}

/**
 * inner enumerator constructor for Peer cfgs
 */
static enumerator_t *peer_enum_create(backend_t *backend, peer_data_t *data)
{
	return backend->create_peer_cfg_enumerator(backend, data->me, data->other);
}
/**
 * inner enumerator constructor for all Peer cfgs
 */
static enumerator_t *peer_enum_create_all(backend_t *backend)
{
	return backend->create_peer_cfg_enumerator(backend, NULL, NULL);
}

/**
 * get a match of a candidate ike_cfg for two hosts
 */
static ike_cfg_match_t get_match(ike_cfg_t *cand, host_t *me, host_t *other)
{
	host_t *me_cand, *other_cand;
	ike_cfg_match_t match = MATCH_NONE;
	
	me_cand = host_create_from_dns(cand->get_my_addr(cand),
								   me->get_family(me), 0);
	if (!me_cand)
	{
		return MATCH_NONE;
	}
	if (me_cand->ip_equals(me_cand, me))
	{
		match += MATCH_ME;
	}
	else if (me_cand->is_anyaddr(me_cand))
	{
		match += MATCH_ANY;
	}
	me_cand->destroy(me_cand);
	
	other_cand = host_create_from_dns(cand->get_other_addr(cand),
									  other->get_family(other), 0);
	if (!other_cand)
	{
		return MATCH_NONE;
	}
	if (other_cand->ip_equals(other_cand, other))
	{
		match += MATCH_OTHER;
	}
	else if (other_cand->is_anyaddr(other_cand))
	{
		match += MATCH_ANY;
	}
	other_cand->destroy(other_cand);
	return match;
}

/**
 * implements backend_manager_t.get_ike_cfg.
 */
static ike_cfg_t *get_ike_cfg(private_backend_manager_t *this, 
							  host_t *me, host_t *other)
{
	ike_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;
	ike_cfg_match_t match, best = MATCH_ANY;
	ike_data_t *data;
	
	data = malloc_thing(ike_data_t);
	data->this = this;
	data->me = me;
	data->other = other;
	
	DBG2(DBG_CFG, "looking for an ike config for %H...%H", me, other);
	
	this->lock->read_lock(this->lock);
	enumerator = enumerator_create_nested(
						this->backends->create_enumerator(this->backends),
						(void*)ike_enum_create, data, (void*)free);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		match = get_match(current, me, other);
		
		if (match)
		{
			DBG2(DBG_CFG, "  candidate: %s...%s, prio %d", 
				 current->get_my_addr(current), 
				 current->get_other_addr(current), match);
			if (match > best)
			{
				DESTROY_IF(found);
				found = current;
				found->get_ref(found);
				best = match;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	if (found)
	{
		DBG2(DBG_CFG, "found matching ike config: %s...%s with prio %d", 
			 found->get_my_addr(found), found->get_other_addr(found), best);
	}
	return found;
}


static enumerator_t *create_peer_cfg_enumerator(private_backend_manager_t *this)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_nested(
							this->backends->create_enumerator(this->backends),
							(void*)peer_enum_create_all, this->lock,
							(void*)this->lock->unlock);
}

/**
 * implements backend_manager_t.get_peer_cfg.
 */			
static peer_cfg_t *get_peer_cfg(private_backend_manager_t *this, host_t *me,
								host_t *other, identification_t *my_id,
								identification_t *other_id, auth_info_t *auth)
{
	peer_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;
	id_match_t best_peer = ID_MATCH_NONE;
	ike_cfg_match_t best_ike = MATCH_NONE;
	peer_data_t *data;
	
	DBG2(DBG_CFG, "looking for a peer config for %H[%D]...%H[%D]",
		 me, my_id, other, other_id);
	
	data = malloc_thing(peer_data_t);
	data->this = this;
	data->me = my_id;
	data->other = other_id;
	
	this->lock->read_lock(this->lock);
	enumerator = enumerator_create_nested(
						this->backends->create_enumerator(this->backends),
						(void*)peer_enum_create, data, (void*)free);
	while (enumerator->enumerate(enumerator, &current))
	{
		identification_t *my_cand, *other_cand;
		id_match_t m1, m2, match_peer;
		ike_cfg_match_t match_ike;
		
		my_cand = current->get_my_id(current);
		other_cand = current->get_other_id(current);
		
		/* own ID may have wildcards in both, config and request (missing IDr) */
		m1 = my_cand->matches(my_cand, my_id);
		if (!m1)
		{
			m1 = my_id->matches(my_id, my_cand);
		}
		m2 = other_id->matches(other_id, other_cand);
		
		match_peer = m1 + m2;
		match_ike = get_match(current->get_ike_cfg(current), me, other);
		
		if (m1 && m2 && match_ike && 
			auth->complies(auth, current->get_auth(current)))
		{
			DBG2(DBG_CFG, "  candidate \"%s\": %D...%D with prio %d.%d",
			 	 current->get_name(current), my_cand, other_cand,
			 	 match_peer, match_ike);
			if (match_peer > best_peer && match_ike >= best_ike)
			{
				DESTROY_IF(found);
				found = current;
				found->get_ref(found);
				best_peer = match_peer;
				best_ike = match_ike;
			}
		}
	}
	if (found)
	{
		DBG1(DBG_CFG, "found matching peer config \"%s\": %D...%D with prio %d.%d",
			 found->get_name(found), found->get_my_id(found),
			 found->get_other_id(found), best_peer, best_ike);
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return found;
}

/**
 * implements backend_manager_t.get_peer_cfg_by_name.
 */			
static peer_cfg_t *get_peer_cfg_by_name(private_backend_manager_t *this, char *name)
{
	backend_t *backend;
	peer_cfg_t *config = NULL;
	enumerator_t *enumerator;
	
	this->lock->read_lock(this->lock);
	enumerator = this->backends->create_enumerator(this->backends);
	while (config == NULL && enumerator->enumerate(enumerator, (void**)&backend))
	{
		config = backend->get_peer_cfg_by_name(backend, name);
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return config;
}

/**
 * Implementation of backend_manager_t.remove_backend.
 */
static void remove_backend(private_backend_manager_t *this, backend_t *backend)
{
	this->lock->write_lock(this->lock);
	this->backends->remove(this->backends, backend, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of backend_manager_t.add_backend.
 */
static void add_backend(private_backend_manager_t *this, backend_t *backend)
{
	this->lock->write_lock(this->lock);
	this->backends->insert_last(this->backends, backend);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of backend_manager_t.destroy.
 */
static void destroy(private_backend_manager_t *this)
{
	this->backends->destroy(this->backends);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * Described in header-file
 */
backend_manager_t *backend_manager_create()
{
	private_backend_manager_t *this = malloc_thing(private_backend_manager_t);
	
	this->public.get_ike_cfg = (ike_cfg_t* (*)(backend_manager_t*, host_t*, host_t*))get_ike_cfg;
	this->public.get_peer_cfg = (peer_cfg_t* (*)(backend_manager_t*,host_t*,host_t*,identification_t*,identification_t*,auth_info_t*))get_peer_cfg;
	this->public.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_manager_t*,char*))get_peer_cfg_by_name;
	this->public.create_peer_cfg_enumerator = (enumerator_t* (*)(backend_manager_t*))create_peer_cfg_enumerator;
	this->public.add_backend = (void(*)(backend_manager_t*, backend_t *backend))add_backend;
	this->public.remove_backend = (void(*)(backend_manager_t*, backend_t *backend))remove_backend;
	this->public.destroy = (void (*)(backend_manager_t*))destroy;
	
	this->backends = linked_list_create();
	this->lock = rwlock_create(RWLOCK_DEFAULT);
	
	return &this->public;
}

