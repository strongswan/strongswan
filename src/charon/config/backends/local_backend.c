/**
 * @file local_backend.c
 *
 * @brief Implementation of local_backend_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "local_backend.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <crypto/ca.h>


typedef struct private_local_backend_t private_local_backend_t;

/**
 * Private data of an local_backend_t object
 */
struct private_local_backend_t {

	/**
	 * Public part
	 */
	local_backend_t public;
	
	/**
	 * list of configs
	 */
	linked_list_t *cfgs;
	
	/**
	 * Mutex to exclusivly access list
	 */
	pthread_mutex_t mutex;
};

/**
 * implements backen_t.get_ike_cfg.
 */
static ike_cfg_t *get_ike_cfg(private_local_backend_t *this, 
							  host_t *my_host, host_t *other_host)
{
	peer_cfg_t *peer;
	ike_cfg_t *current, *found = NULL;
	iterator_t *iterator;
	host_t *my_candidate, *other_candidate;
	enum {
		MATCH_NONE  = 0x00,
		MATCH_ANY   = 0x01,
		MATCH_ME    = 0x04,
		MATCH_OTHER = 0x08,
	} prio, best = MATCH_ANY;
	
	DBG2(DBG_CFG, "looking for a config for %H...%H",
		 my_host, other_host);
	
	iterator = this->cfgs->create_iterator_locked(this->cfgs, &this->mutex);
	while (iterator->iterate(iterator, (void**)&peer))
	{
		prio = MATCH_NONE;
		current = peer->get_ike_cfg(peer);
		my_candidate = current->get_my_host(current);
		other_candidate = current->get_other_host(current);
		
		if (my_candidate->ip_equals(my_candidate, my_host))
		{
			prio += MATCH_ME;
		}
		else if (my_candidate->is_anyaddr(my_candidate))
		{
			prio += MATCH_ANY;
		}
		
		if (other_candidate->ip_equals(other_candidate, other_host))
		{
			prio += MATCH_OTHER;
		}
		else if (other_candidate->is_anyaddr(other_candidate))
		{
			prio += MATCH_ANY;
		}
		
		DBG2(DBG_CFG, "  candidate '%s': %H...%H, prio %d",
			 peer->get_name(peer), my_candidate, other_candidate, prio);
		
		/* we require at least two MATCH_ANY */
		if (prio > best)
		{
			best = prio;
			found = current;
		}
	}
	if (found)
	{
		found->get_ref(found);
	}
	iterator->destroy(iterator);
	return found;
}

#define PRIO_NO_MATCH_FOUND		256

/**
 * implements backend_t.get_peer.
 */			
static peer_cfg_t *get_peer_cfg(private_local_backend_t *this,
								identification_t *my_id, identification_t *other_id,
								ca_info_t *other_ca_info)
{
	peer_cfg_t *current, *found = NULL;
	iterator_t *iterator;
	identification_t *my_candidate, *other_candidate;
	int best = PRIO_NO_MATCH_FOUND;
	
	DBG2(DBG_CFG, "looking for a config for %D...%D", my_id, other_id);
	
	iterator = this->cfgs->create_iterator_locked(this->cfgs, &this->mutex);
	while (iterator->iterate(iterator, (void**)&current))
	{
		int wc1, wc2;

		my_candidate = current->get_my_id(current);
		other_candidate = current->get_other_id(current);

		if (my_candidate->matches(my_candidate, my_id, &wc1)
		&&	other_id->matches(other_id, other_candidate, &wc2))
		{
			int prio = (wc1 + wc2) * (MAX_CA_PATH_LEN + 1);
			int pathlen = 0;
			identification_t *other_candidate_ca = current->get_other_ca(current);
			linked_list_t *groups = current->get_groups(current);

			/* is a group membership required? */
			if (groups->get_count(groups) > 0)
			{
				DBG1(DBG_CFG, "  group membership required");
			}

			/* are there any ca constraints? */
			if (other_candidate_ca->get_type(other_candidate_ca) != ID_ANY)
			{
				ca_info_t *ca_info = other_ca_info;

				for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
				{
					if (ca_info == NULL)
					{
						prio = PRIO_NO_MATCH_FOUND;
						break;
					}
					else
					{
						x509_t *cacert = ca_info->get_certificate(ca_info);
						identification_t *other_ca = cacert->get_subject(cacert);

						if (other_candidate_ca->equals(other_candidate_ca, other_ca))
						{
							/* found a ca match */
							break;
						}
						if (cacert->is_self_signed(cacert))
						{
							/* reached the root ca without a match */
							prio = PRIO_NO_MATCH_FOUND;
							break;
						}
						/* move a level upward in the trust path hierarchy */
						ca_info = charon->credentials->get_issuer(charon->credentials, cacert); 
					}
				}
				if (pathlen == MAX_CA_PATH_LEN)
				{
					DBG1(DBG_CFG, "maximum ca path length of %d levels reached", MAX_CA_PATH_LEN);
					prio = PRIO_NO_MATCH_FOUND;
				}
			}
			if (prio == PRIO_NO_MATCH_FOUND)
			{
				DBG2(DBG_CFG, "  candidate '%s': %D...%D, no ca match",
				 	current->get_name(current), my_candidate, other_candidate);
			}
			else
			{
				prio += pathlen;
				DBG2(DBG_CFG, "  candidate '%s': %D...%D, prio %d",
				 	current->get_name(current), my_candidate, other_candidate, prio);
			
				if (prio < best)
				{
					found = current;
					best = prio;
				}
			}
		}
	}
	if (found)
	{
		DBG1(DBG_CFG, "found matching config \"%s\": %D...%D, prio %d",
				found->get_name(found),
				found->get_my_id(found),
				found->get_other_id(found),
				best);
		found->get_ref(found);
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of backend_t.is_writable.
 */
static bool is_writeable(private_local_backend_t *this)
{
    return TRUE;
}

/**
 * Implementation of writable_backend_t.create_iterator.
 */
static iterator_t* create_iterator(private_local_backend_t *this)
{
	return this->cfgs->create_iterator_locked(this->cfgs, &this->mutex);
}

/**
 * Implementation of writable_backend_t.add_peer_cfg.
 */
static void add_cfg(private_local_backend_t *this, peer_cfg_t *config)
{
    pthread_mutex_lock(&this->mutex);
    this->cfgs->insert_last(this->cfgs, config);
    pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of backend_t.destroy.
 */
static void destroy(private_local_backend_t *this)
{
    this->cfgs->destroy_offset(this->cfgs, offsetof(peer_cfg_t, destroy));
    free(this);
}

/**
 * Described in header.
 */
backend_t *backend_create(void)
{
	private_local_backend_t *this = malloc_thing(private_local_backend_t);
	
	this->public.backend.backend.get_ike_cfg = (ike_cfg_t* (*)(backend_t*, host_t*, host_t*))get_ike_cfg;
	this->public.backend.backend.get_peer_cfg = (peer_cfg_t* (*)(backend_t*,identification_t*,identification_t*,ca_info_t*))get_peer_cfg;
    this->public.backend.backend.is_writeable = (bool(*) (backend_t*))is_writeable;
    this->public.backend.backend.destroy = (void (*)(backend_t*))destroy;
	this->public.backend.create_iterator = (iterator_t* (*)(writeable_backend_t*))create_iterator;
    this->public.backend.add_cfg = (void (*)(writeable_backend_t*,peer_cfg_t*))add_cfg;
    
	/* private variables */
	this->cfgs = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	
	return &this->public.backend.backend;
}
