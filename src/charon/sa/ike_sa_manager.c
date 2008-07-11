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
 *
 * $Id$
 */

#include <pthread.h>
#include <string.h>

#include "ike_sa_manager.h"

#include <daemon.h>
#include <sa/ike_sa_id.h>
#include <bus/bus.h>
#include <utils/linked_list.h>
#include <crypto/hashers/hasher.h>

typedef struct entry_t entry_t;

/**
 * An entry in the linked list, contains IKE_SA, locking and lookup data.
 */
struct entry_t {
	
	/**
	 * Number of threads waiting for this ike_sa_t object.
	 */
	int waiting_threads;
	
	/**
	 * Condvar where threads can wait until ike_sa_t object is free for use again.
	 */
	pthread_cond_t condvar;
	
	/**
	 * Is this ike_sa currently checked out?
	 */
	bool checked_out;
	
	/**
	 * Does this SA drives out new threads?
	 */
	bool driveout_new_threads;
	
	/**
	 * Does this SA drives out waiting threads?
	 */
	bool driveout_waiting_threads;
	
	/**
	 * Identifiaction of an IKE_SA (SPIs).
	 */
	ike_sa_id_t *ike_sa_id;
	
	/**
	 * The contained ike_sa_t object.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * hash of the IKE_SA_INIT message, used to detect retransmissions
	 */
	chunk_t init_hash;
	
	/**
	 * remote host address, required for DoS detection
	 */
	host_t *other;
	
	/**
	 * message ID currently processing, if any
	 */
	u_int32_t message_id;
};

/**
 * Implementation of entry_t.destroy.
 */
static status_t entry_destroy(entry_t *this)
{
	/* also destroy IKE SA */
	this->ike_sa->destroy(this->ike_sa);
	this->ike_sa_id->destroy(this->ike_sa_id);
	chunk_free(&this->init_hash);
	DESTROY_IF(this->other);
	free(this);
	return SUCCESS;
}

/**
 * Creates a new entry for the ike_sa_t list.
 */
static entry_t *entry_create(ike_sa_id_t *ike_sa_id)
{
	entry_t *this = malloc_thing(entry_t);
	
	this->waiting_threads = 0;
	pthread_cond_init(&this->condvar, NULL);
	
	/* we set checkout flag when we really give it out */
	this->checked_out = FALSE;
	this->driveout_new_threads = FALSE;
	this->driveout_waiting_threads = FALSE;
	this->message_id = -1;
	this->init_hash = chunk_empty;
	this->other = NULL;
	
	/* ike_sa_id is always cloned */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);

	/* create new ike_sa */
	this->ike_sa = ike_sa_create(ike_sa_id);

	return this;
}


typedef struct private_ike_sa_manager_t private_ike_sa_manager_t;

/**
 * Additional private members of ike_sa_manager_t.
 */
struct private_ike_sa_manager_t {
	/**
	 * Public interface of ike_sa_manager_t.
	 */
	 ike_sa_manager_t public;
	
	 /**
	  * Lock for exclusivly accessing the manager.
	  */
	 pthread_mutex_t mutex;

	 /**
	  * Linked list with entries for the ike_sa_t objects.
	  */
	 linked_list_t *ike_sa_list;
	 
	 /**
	  * RNG to get random SPIs for our side
	  */
	 rng_t *rng;
	 
	 /**
	  * SHA1 hasher for IKE_SA_INIT retransmit detection
	  */
	 hasher_t *hasher;
	
	/**
	 * reuse existing IKE_SAs in checkout_by_config
	 */
	 bool reuse_ikesa;
};

/**
 * Implementation of private_ike_sa_manager_t.get_entry_by_id.
 */
static status_t get_entry_by_id(private_ike_sa_manager_t *this,
								ike_sa_id_t *ike_sa_id, entry_t **entry)
{
	enumerator_t *enumerator;
	entry_t *current;
	status_t status;
	
	/* create enumerator over list of ike_sa's */
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);

	/* default status */
	status = NOT_FOUND;
	
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->ike_sa_id->equals(current->ike_sa_id, ike_sa_id))
		{
			DBG2(DBG_MGR,  "found entry by both SPIs");
			*entry = current;
			status = SUCCESS;
			break;
		}
		if (ike_sa_id->get_responder_spi(ike_sa_id) == 0 ||
			current->ike_sa_id->get_responder_spi(current->ike_sa_id) == 0)
		{
			/* seems to be a half ready ike_sa */
			if ((current->ike_sa_id->get_initiator_spi(current->ike_sa_id) ==
						  ike_sa_id->get_initiator_spi(ike_sa_id)) &&
				(current->ike_sa_id->is_initiator(ike_sa_id) ==
						  ike_sa_id->is_initiator(current->ike_sa_id)))
			{
				DBG2(DBG_MGR, "found entry by initiator SPI");
				*entry = current;
				status = SUCCESS;
				break;
			}
		}
	}
	
	enumerator->destroy(enumerator);
	return status;
}

/**
 * Implementation of private_ike_sa_manager_t.get_entry_by_sa.
 */
static status_t get_entry_by_sa(private_ike_sa_manager_t *this,
								ike_sa_t *ike_sa, entry_t **entry)
{
	enumerator_t *enumerator;
	entry_t *current;
	status_t status;
	
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	
	/* default status */
	status = NOT_FOUND;
	
	while (enumerator->enumerate(enumerator, &current))
	{
		/* only pointers are compared */
		if (current->ike_sa == ike_sa)
		{
			DBG2(DBG_MGR, "found entry by pointer");
			*entry = current;
			status = SUCCESS;
			break;
		}
	}
	enumerator->destroy(enumerator);
	
	return status;
}

/**
 * Implementation of private_ike_sa_manager_s.delete_entry.
 */
static status_t delete_entry(private_ike_sa_manager_t *this, entry_t *entry)
{
	enumerator_t *enumerator;
	entry_t *current;
	status_t status;
	
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);

	status = NOT_FOUND;
	
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current == entry)
		{
			/* mark it, so now new threads can get this entry */
			entry->driveout_new_threads = TRUE;
			/* wait until all workers have done their work */
			while (entry->waiting_threads)
			{
				/* wake up all */
				pthread_cond_broadcast(&(entry->condvar));
				/* they will wake us again when their work is done */
				pthread_cond_wait(&(entry->condvar), &(this->mutex));
			}
			
			DBG2(DBG_MGR,  "found entry by pointer, deleting it");
			this->ike_sa_list->remove_at(this->ike_sa_list, enumerator);
			entry_destroy(entry);
			status = SUCCESS;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return status;
}

/**
 * Wait until no other thread is using an IKE_SA, return FALSE if entry not
 * acquireable
 */
static bool wait_for_entry(private_ike_sa_manager_t *this, entry_t *entry)
{
	if (entry->driveout_new_threads)
	{
		/* we are not allowed to get this */
		return FALSE;
	}
	while (entry->checked_out && !entry->driveout_waiting_threads)	
	{
		/* so wait until we can get it for us.
		 * we register us as waiting. */
		entry->waiting_threads++;
		pthread_cond_wait(&(entry->condvar), &(this->mutex));
		entry->waiting_threads--;
	}
	/* hm, a deletion request forbids us to get this SA, get next one */
	if (entry->driveout_waiting_threads)
	{
		/* we must signal here, others may be waiting on it, too */
		pthread_cond_signal(&(entry->condvar));
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of private_ike_sa_manager_t.get_next_spi.
 */
static u_int64_t get_next_spi(private_ike_sa_manager_t *this)
{
	u_int64_t spi;
	
	this->rng->get_bytes(this->rng, sizeof(spi), (u_int8_t*)&spi);
	return spi;
}

/**
 * Implementation of of ike_sa_manager.checkout.
 */
static ike_sa_t* checkout(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id)
{
	ike_sa_t *ike_sa = NULL;
	entry_t *entry;
	
	DBG2(DBG_MGR, "checkout IKE_SA, %d IKE_SAs in manager",
		 this->ike_sa_list->get_count(this->ike_sa_list));
	
	pthread_mutex_lock(&(this->mutex));
	if (get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
	{
		if (wait_for_entry(this, entry))
		{
			DBG2(DBG_MGR, "IKE_SA successfully checked out");
			entry->checked_out = TRUE;
			ike_sa = entry->ike_sa;
		}
	}
	pthread_mutex_unlock(&this->mutex);
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout_new.
 */
static ike_sa_t *checkout_new(private_ike_sa_manager_t* this, bool initiator)
{
	entry_t *entry;
	ike_sa_id_t *id;
	
	if (initiator)
	{
		id = ike_sa_id_create(get_next_spi(this), 0, TRUE);
	}
	else
	{
		id = ike_sa_id_create(0, get_next_spi(this), FALSE);
	}
	entry = entry_create(id);
	id->destroy(id);
	pthread_mutex_lock(&this->mutex);	
	this->ike_sa_list->insert_last(this->ike_sa_list, entry);
	entry->checked_out = TRUE;
	pthread_mutex_unlock(&this->mutex);	
	DBG2(DBG_MGR, "created IKE_SA, %d IKE_SAs in manager",
		 this->ike_sa_list->get_count(this->ike_sa_list));
	return entry->ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_message.
 */
static ike_sa_t* checkout_by_message(private_ike_sa_manager_t* this,
									 message_t *message)
{
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	ike_sa_id_t *id = message->get_ike_sa_id(message);
	id = id->clone(id);
	id->switch_initiator(id);
	
	DBG2(DBG_MGR, "checkout IKE_SA by message, %d IKE_SAs in manager",
		 this->ike_sa_list->get_count(this->ike_sa_list));
	
	if (message->get_request(message) &&
		message->get_exchange_type(message) == IKE_SA_INIT)
	{
		/* IKE_SA_INIT request. Check for an IKE_SA with such a message hash. */
		enumerator_t *enumerator;
		chunk_t data, hash;
		
		data = message->get_packet_data(message);
		this->hasher->allocate_hash(this->hasher, data, &hash);
		chunk_free(&data);
		
		pthread_mutex_lock(&this->mutex);
		enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (chunk_equals(hash, entry->init_hash))
			{
				if (entry->message_id == 0)
				{
					enumerator->destroy(enumerator);
					pthread_mutex_unlock(&this->mutex);
					chunk_free(&hash);
					id->destroy(id);
					DBG1(DBG_MGR, "ignoring IKE_SA_INIT, already processing");
					return NULL;
				}
				else if (wait_for_entry(this, entry))
				{
					DBG2(DBG_MGR, "IKE_SA checked out by hash");
					entry->checked_out = TRUE;
					entry->message_id = message->get_message_id(message);
					ike_sa = entry->ike_sa;
				}
				break;
			}
		}
		enumerator->destroy(enumerator);
		pthread_mutex_unlock(&this->mutex);
		
		if (ike_sa == NULL)
		{
			if (id->get_responder_spi(id) == 0 &&
				message->get_exchange_type(message) == IKE_SA_INIT)
			{
				/* no IKE_SA found, create a new one */
				id->set_responder_spi(id, get_next_spi(this));
				entry = entry_create(id);
				
				pthread_mutex_lock(&this->mutex);
				this->ike_sa_list->insert_last(this->ike_sa_list, entry);
				entry->checked_out = TRUE;
				entry->message_id = message->get_message_id(message);
				pthread_mutex_unlock(&this->mutex);
				entry->init_hash = hash;
				ike_sa = entry->ike_sa;
			}
			else
			{
				chunk_free(&hash);
				DBG1(DBG_MGR, "ignoring message, no such IKE_SA");
			}
		}
		else
		{
			chunk_free(&hash);
		}
		id->destroy(id);
		charon->bus->set_sa(charon->bus, ike_sa);
		return ike_sa;
	}
	
	pthread_mutex_lock(&(this->mutex));
	if (get_entry_by_id(this, id, &entry) == SUCCESS)
	{
		/* only check out if we are not processing this request */
		if (message->get_request(message) &&
			message->get_message_id(message) == entry->message_id)
		{
			DBG1(DBG_MGR, "ignoring request with ID %d, already processing",
				 entry->message_id);
		}
		else if (wait_for_entry(this, entry))
		{
			ike_sa_id_t *ike_id = entry->ike_sa->get_id(entry->ike_sa);
			DBG2(DBG_MGR, "IKE_SA successfully checked out");
			entry->checked_out = TRUE;
			entry->message_id = message->get_message_id(message);
			if (ike_id->get_responder_spi(ike_id) == 0)
			{
				ike_id->set_responder_spi(ike_id, id->get_responder_spi(id));
			}
			ike_sa = entry->ike_sa;
		}
	}
	pthread_mutex_unlock(&this->mutex);
	id->destroy(id);
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_config.
 */
static ike_sa_t* checkout_by_config(private_ike_sa_manager_t *this,
									peer_cfg_t *peer_cfg)
{
	enumerator_t *enumerator;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	identification_t *my_id, *other_id;
	host_t *my_host, *other_host;
	ike_cfg_t *ike_cfg;
	
	ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
	my_id = peer_cfg->get_my_id(peer_cfg);
	other_id = peer_cfg->get_other_id(peer_cfg);
	my_host = host_create_from_dns(ike_cfg->get_my_addr(ike_cfg), 0, 0);
	other_host = host_create_from_dns(ike_cfg->get_other_addr(ike_cfg), 0, 0);
	
	pthread_mutex_lock(&(this->mutex));
	
	if (my_host && other_host && this->reuse_ikesa)
	{
		enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
		while (enumerator->enumerate(enumerator, &entry))
		{
			identification_t *found_my_id, *found_other_id;
			host_t *found_my_host, *found_other_host;
		
			if (!wait_for_entry(this, entry))
			{
				continue;
			}
		
			if (entry->ike_sa->get_state(entry->ike_sa) == IKE_DELETING)
			{
				/* skip IKE_SA which are not useable */
				continue;
			}
		
			found_my_id = entry->ike_sa->get_my_id(entry->ike_sa);
			found_other_id = entry->ike_sa->get_other_id(entry->ike_sa);
			found_my_host = entry->ike_sa->get_my_host(entry->ike_sa);
			found_other_host = entry->ike_sa->get_other_host(entry->ike_sa);
		
			if (found_my_id->get_type(found_my_id) == ID_ANY &&
				found_other_id->get_type(found_other_id) == ID_ANY)
			{
				/* IKE_SA has no IDs yet, so we can't use it */
				continue;
			}
			DBG2(DBG_MGR, "candidate IKE_SA for \n\t"
				 "%H[%D]...%H[%D]\n\t%H[%D]...%H[%D]",
				 my_host, my_id, other_host, other_id,
				 found_my_host, found_my_id, found_other_host, found_other_id);
			/* compare ID and hosts. Supplied ID may contain wildcards, and IP
			 * may be %any. */
			if ((my_host->is_anyaddr(my_host) ||
				 my_host->ip_equals(my_host, found_my_host)) &&
				(other_host->is_anyaddr(other_host) ||
				 other_host->ip_equals(other_host, found_other_host)) &&
				found_my_id->matches(found_my_id, my_id) &&
				found_other_id->matches(found_other_id, other_id) &&
				streq(peer_cfg->get_name(peer_cfg),
					  entry->ike_sa->get_name(entry->ike_sa)))
			{
				/* looks good, we take this one */
				DBG2(DBG_MGR, "found an existing IKE_SA for %H[%D]...%H[%D]",
					 my_host, my_id, other_host, other_id);
				entry->checked_out = TRUE;
				ike_sa = entry->ike_sa;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	DESTROY_IF(my_host);
	DESTROY_IF(other_host);
	
	if (!ike_sa)
	{
		u_int64_t initiator_spi;
		entry_t *new_entry;
		ike_sa_id_t *new_ike_sa_id;
		
		initiator_spi = get_next_spi(this);
		new_ike_sa_id = ike_sa_id_create(0, 0, TRUE);
		new_ike_sa_id->set_initiator_spi(new_ike_sa_id, initiator_spi);
		
		/* create entry */
		new_entry = entry_create(new_ike_sa_id);
		DBG2(DBG_MGR, "created IKE_SA");
		new_ike_sa_id->destroy(new_ike_sa_id);
		
		this->ike_sa_list->insert_last(this->ike_sa_list, new_entry);
		
		/* check ike_sa out */
		DBG2(DBG_MGR, "new IKE_SA created for IDs [%D]...[%D]", my_id, other_id);
		new_entry->checked_out = TRUE;
		ike_sa = new_entry->ike_sa;
	}
	pthread_mutex_unlock(&(this->mutex));
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_id.
 */
static ike_sa_t* checkout_by_id(private_ike_sa_manager_t *this, u_int32_t id,
								bool child)
{
	enumerator_t *enumerator;
	iterator_t *children;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	child_sa_t *child_sa;
	
	pthread_mutex_lock(&(this->mutex));
	
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (wait_for_entry(this, entry))
		{
			/* look for a child with such a reqid ... */
			if (child)
			{
				children = entry->ike_sa->create_child_sa_iterator(entry->ike_sa);
				while (children->iterate(children, (void**)&child_sa))
				{
					if (child_sa->get_reqid(child_sa) == id)
					{
						ike_sa = entry->ike_sa;
						break;
					}		
				}
				children->destroy(children);
			}
			else /* ... or for a IKE_SA with such a unique id */
			{
				if (entry->ike_sa->get_unique_id(entry->ike_sa) == id)
				{
					ike_sa = entry->ike_sa;
				}
			}
			/* got one, return */
			if (ike_sa)
			{
				entry->checked_out = TRUE;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pthread_mutex_unlock(&(this->mutex));
	
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_name.
 */
static ike_sa_t* checkout_by_name(private_ike_sa_manager_t *this, char *name,
								  bool child)
{
	enumerator_t *enumerator;
	iterator_t *children;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	child_sa_t *child_sa;
	
	pthread_mutex_lock(&(this->mutex));
	
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (wait_for_entry(this, entry))
		{
			/* look for a child with such a policy name ... */
			if (child)
			{
				children = entry->ike_sa->create_child_sa_iterator(entry->ike_sa);
				while (children->iterate(children, (void**)&child_sa))
				{
					if (streq(child_sa->get_name(child_sa), name))
					{
						ike_sa = entry->ike_sa;
						break;
					}		
				}
				children->destroy(children);
			}
			else /* ... or for a IKE_SA with such a connection name */
			{
				if (streq(entry->ike_sa->get_name(entry->ike_sa), name))
				{
					ike_sa = entry->ike_sa;
				}
			}
			/* got one, return */
			if (ike_sa)
			{
				entry->checked_out = TRUE;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pthread_mutex_unlock(&(this->mutex));
	
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}
	
/**
 * Implementation of ike_sa_manager_t.checkout_duplicate.
 */
static ike_sa_t* checkout_duplicate(private_ike_sa_manager_t *this,
									ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	entry_t *entry;
	ike_sa_t *duplicate = NULL;
	identification_t *me, *other;
	
	me = ike_sa->get_my_id(ike_sa);
	other = ike_sa->get_other_id(ike_sa);
	
	pthread_mutex_lock(&this->mutex);
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->ike_sa == ike_sa)
		{	/* self is not a duplicate */
			continue;
		}
		if (wait_for_entry(this, entry))
		{
			if (me->equals(me, entry->ike_sa->get_my_id(entry->ike_sa)) &&
				other->equals(other, entry->ike_sa->get_other_id(entry->ike_sa)))
			{
				duplicate = entry->ike_sa;
				entry->checked_out = TRUE;
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	pthread_mutex_unlock(&this->mutex);
	return duplicate;
}

/**
 * enumerator cleanup function
 */
static void enumerator_unlock(private_ike_sa_manager_t *this)
{
	pthread_mutex_unlock(&this->mutex);
}

/**
 * enumerator filter function 
 */
static bool enumerator_filter(private_ike_sa_manager_t *this,
							  entry_t **in, ike_sa_t **out)
{
	if (wait_for_entry(this, *in))
	{
		*out = (*in)->ike_sa;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of ike_sa_manager_t.create_iterator.
 */
static enumerator_t *create_enumerator(private_ike_sa_manager_t* this)
{
	pthread_mutex_lock(&this->mutex);
	return enumerator_create_filter(
						this->ike_sa_list->create_enumerator(this->ike_sa_list),
						(void*)enumerator_filter, this, (void*)enumerator_unlock);
}

/**
 * Implementation of ike_sa_manager_t.checkin.
 */
static status_t checkin(private_ike_sa_manager_t *this, ike_sa_t *ike_sa)
{
	/* to check the SA back in, we look for the pointer of the ike_sa
	 * in all entries.
	 * We can't search by SPI's since the MAY have changed (e.g. on reception
	 * of a IKE_SA_INIT response). Updating of the SPI MAY be necessary...
	 */
	status_t retval;
	entry_t *entry;
	ike_sa_id_t *ike_sa_id;
	host_t *other;
	
	ike_sa_id = ike_sa->get_id(ike_sa);
	
	DBG2(DBG_MGR, "checkin IKE_SA");
	
	pthread_mutex_lock(&(this->mutex));

	/* look for the entry */
	if (get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* ike_sa_id must be updated */
		entry->ike_sa_id->replace_values(entry->ike_sa_id, ike_sa->get_id(ike_sa));
		/* signal waiting threads */
		entry->checked_out = FALSE;
		entry->message_id = -1;
		/* apply remote address for DoS detection */
		other = ike_sa->get_other_host(ike_sa);
		if (!entry->other || !other->equals(other, entry->other))
		{
			DESTROY_IF(entry->other);
			entry->other = other->clone(other);
		}
		DBG2(DBG_MGR, "check-in of IKE_SA successful.");
		pthread_cond_signal(&(entry->condvar));
	 	retval = SUCCESS;
	}
	else
	{
		DBG2(DBG_MGR, "tried to check in nonexisting IKE_SA");
		/* this SA is no more, this REALLY should not happen */
		retval = NOT_FOUND;
	}
	
	DBG2(DBG_MGR, "%d IKE_SAs in manager now",
		 this->ike_sa_list->get_count(this->ike_sa_list));
	pthread_mutex_unlock(&(this->mutex));
	
	charon->bus->set_sa(charon->bus, NULL);
	return retval;
}


/**
 * Implementation of ike_sa_manager_t.checkin_and_destroy.
 */
static status_t checkin_and_destroy(private_ike_sa_manager_t *this, ike_sa_t *ike_sa)
{
	/* deletion is a bit complex, we must garant that no thread is waiting for
	 * this SA.
	 * We take this SA from the list, and start signaling while threads
	 * are in the condvar.
	 */
	entry_t *entry;
	status_t retval;
	ike_sa_id_t *ike_sa_id;
	
	ike_sa_id = ike_sa->get_id(ike_sa);
	DBG2(DBG_MGR, "checkin and destroy IKE_SA");
	charon->bus->set_sa(charon->bus, NULL);

	pthread_mutex_lock(&(this->mutex));

	if (get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* drive out waiting threads, as we are in hurry */
		entry->driveout_waiting_threads = TRUE;
		
		delete_entry(this, entry);
		
		DBG2(DBG_MGR, "check-in and destroy of IKE_SA successful");
		retval = SUCCESS;
	}
	else
	{
		DBG2(DBG_MGR, "tried to check-in and delete nonexisting IKE_SA");
		retval = NOT_FOUND;
	}
	
	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

/**
 * Implementation of ike_sa_manager_t.get_half_open_count.
 */
static int get_half_open_count(private_ike_sa_manager_t *this, host_t *ip)
{
	enumerator_t *enumerator;
	entry_t *entry;
	int count = 0;

	pthread_mutex_lock(&(this->mutex));
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		/* we check if we have a responder CONNECTING IKE_SA without checkout */
		if (!entry->ike_sa_id->is_initiator(entry->ike_sa_id) &&
			entry->ike_sa->get_state(entry->ike_sa) == IKE_CONNECTING)
		{
			/* if we have a host, count only matching IKE_SAs */
			if (ip)
			{
				if (entry->other && ip->ip_equals(ip, entry->other))
				{
					count++;
				}
			}
			else
			{
				count++;
			}
		}
	}
	enumerator->destroy(enumerator);
	
	pthread_mutex_unlock(&(this->mutex));
	return count;
}

/**
 * Implementation of ike_sa_manager_t.flush.
 */
static void flush(private_ike_sa_manager_t *this)
{
	/* destroy all list entries */
	enumerator_t *enumerator;
	entry_t *entry;
	
	pthread_mutex_lock(&(this->mutex));
	DBG2(DBG_MGR, "going to destroy IKE_SA manager and all managed IKE_SA's");
	/* Step 1: drive out all waiting threads  */
	DBG2(DBG_MGR, "set driveout flags for all stored IKE_SA's");
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;	
	}
	enumerator->destroy(enumerator);
	DBG2(DBG_MGR, "wait for all threads to leave IKE_SA's");
	/* Step 2: wait until all are gone */
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		while (entry->waiting_threads)
		{
			/* wake up all */
			pthread_cond_broadcast(&(entry->condvar));
			/* go sleeping until they are gone */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
	}
	enumerator->destroy(enumerator);
	DBG2(DBG_MGR, "delete all IKE_SA's");
	/* Step 3: initiate deletion of all IKE_SAs */
	enumerator = this->ike_sa_list->create_enumerator(this->ike_sa_list);
	while (enumerator->enumerate(enumerator, &entry))
	{
		entry->ike_sa->delete(entry->ike_sa);
	}
	enumerator->destroy(enumerator);
	
	DBG2(DBG_MGR, "destroy all entries");
	/* Step 4: destroy all entries */
	while (this->ike_sa_list->remove_last(this->ike_sa_list,
										  (void**)&entry) == SUCCESS)
	{
		entry_destroy(entry);
	}
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of ike_sa_manager_t.destroy.
 */
static void destroy(private_ike_sa_manager_t *this)
{
	this->ike_sa_list->destroy(this->ike_sa_list);
	this->rng->destroy(this->rng);
	this->hasher->destroy(this->hasher);
	
	free(this);
}

/*
 * Described in header.
 */
ike_sa_manager_t *ike_sa_manager_create()
{
	private_ike_sa_manager_t *this = malloc_thing(private_ike_sa_manager_t);

	/* assign public functions */
	this->public.flush = (void(*)(ike_sa_manager_t*))flush;
	this->public.destroy = (void(*)(ike_sa_manager_t*))destroy;
	this->public.checkout = (ike_sa_t*(*)(ike_sa_manager_t*, ike_sa_id_t*))checkout;
	this->public.checkout_new = (ike_sa_t*(*)(ike_sa_manager_t*,bool))checkout_new;
	this->public.checkout_by_message = (ike_sa_t*(*)(ike_sa_manager_t*,message_t*))checkout_by_message;
	this->public.checkout_by_config = (ike_sa_t*(*)(ike_sa_manager_t*,peer_cfg_t*))checkout_by_config;
	this->public.checkout_by_id = (ike_sa_t*(*)(ike_sa_manager_t*,u_int32_t,bool))checkout_by_id;
	this->public.checkout_by_name = (ike_sa_t*(*)(ike_sa_manager_t*,char*,bool))checkout_by_name;
	this->public.checkout_duplicate = (ike_sa_t*(*)(ike_sa_manager_t*, ike_sa_t *ike_sa))checkout_duplicate;
	this->public.create_enumerator = (enumerator_t*(*)(ike_sa_manager_t*))create_enumerator;
	this->public.checkin = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin;
	this->public.checkin_and_destroy = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin_and_destroy;
	this->public.get_half_open_count = (int(*)(ike_sa_manager_t*,host_t*))get_half_open_count;
	
	/* initialize private variables */
	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_PREFERRED);
	if (this->hasher == NULL)
	{
		DBG1(DBG_MGR, "manager initialization failed, no hasher supported");
		free(this);
		return NULL;
	}
	this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (this->rng == NULL)
	{
		DBG1(DBG_MGR, "manager initialization failed, no RNG supported");
		this->hasher->destroy(this->hasher);
		free(this);
		return NULL;
	}
	this->ike_sa_list = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	this->reuse_ikesa = lib->settings->get_bool(lib->settings,
												"charon.reuse_ikesa", TRUE);
	return &this->public;
}

