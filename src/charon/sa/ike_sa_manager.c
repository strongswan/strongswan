/**
 * @file ike_sa_manager.c
 *
 * @brief Implementation of ike_sa_mananger_t.
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

#include <pthread.h>
#include <string.h>

#include "ike_sa_manager.h"

#include <daemon.h>
#include <sa/ike_sa_id.h>
#include <bus/bus.h>
#include <utils/linked_list.h>

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
	  * A randomizer, to get random SPIs for our side
	  */
	 randomizer_t *randomizer;
	 
	 /**
	  * SHA1 hasher for IKE_SA_INIT retransmit detection
	  */
	 hasher_t *hasher;
};

/**
 * Implementation of private_ike_sa_manager_t.get_entry_by_id.
 */
static status_t get_entry_by_id(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, entry_t **entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	entry_t *current;
	status_t status;
	
	/* create iterator over list of ike_sa's */
	iterator = list->create_iterator(list, TRUE);

	/* default status */
	status = NOT_FOUND;
	
	while (iterator->iterate(iterator, (void**)&current))
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
	
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of private_ike_sa_manager_t.get_entry_by_sa.
 */
static status_t get_entry_by_sa(private_ike_sa_manager_t *this, ike_sa_t *ike_sa, entry_t **entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	entry_t *current;
	status_t status;
	
	iterator = list->create_iterator(list, TRUE);
	
	/* default status */
	status = NOT_FOUND;
	
	while (iterator->iterate(iterator, (void**)&current))
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
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implementation of private_ike_sa_manager_s.delete_entry.
 */
static status_t delete_entry(private_ike_sa_manager_t *this, entry_t *entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	entry_t *current;
	status_t status;
	
	iterator = list->create_iterator(list, TRUE);

	status = NOT_FOUND;
	
	while (iterator->iterate(iterator, (void**)&current))
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
			iterator->remove(iterator);
			entry_destroy(entry);
			status = SUCCESS;
			break;
		}
	}
	iterator->destroy(iterator);
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
	
	this->randomizer->get_pseudo_random_bytes(this->randomizer, sizeof(spi),
											  (u_int8_t*)&spi);
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
 * Implementation of of ike_sa_manager.checkout_by_id.
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
		iterator_t *iterator;
		chunk_t data, hash;
		
		data = message->get_packet_data(message);
		this->hasher->allocate_hash(this->hasher, data, &hash);
		chunk_free(&data);
		
		pthread_mutex_lock(&this->mutex);
		iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
		while (iterator->iterate(iterator, (void**)&entry))
		{
			if (chunk_equals(hash, entry->init_hash))
			{
				if (entry->message_id == 0)
				{
					iterator->destroy(iterator);
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
		iterator->destroy(iterator);
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
 * Implementation of of ike_sa_manager.checkout_by_id.
 */
static ike_sa_t* checkout_by_peer(private_ike_sa_manager_t *this,
								  host_t *my_host, host_t *other_host,
								  identification_t *my_id,
								  identification_t *other_id)
{
	iterator_t *iterator;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		identification_t *found_my_id, *found_other_id;
		host_t *found_my_host, *found_other_host;
		int wc;
		
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
		
		/* compare ID and hosts. Supplied ID may contain wildcards, and IP
		 * may be %any. */
		if ((found_my_host->is_anyaddr(found_my_host) ||
			 my_host->ip_equals(my_host, found_my_host)) &&
			(found_other_host->is_anyaddr(found_other_host) ||
			 other_host->ip_equals(other_host, found_other_host)) &&
			found_my_id->matches(found_my_id, my_id, &wc) &&
			found_other_id->matches(found_other_id, other_id, &wc))
		{
			/* looks good, we take this one */
			DBG2(DBG_MGR, "found an existing IKE_SA for %H[%D]...%H[%D]",
				 my_host, other_host, my_id, other_id);
			entry->checked_out = TRUE;
			ike_sa = entry->ike_sa;
		}
	}
	iterator->destroy(iterator);
	
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
	iterator_t *iterator, *children;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	child_sa_t *child_sa;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
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
	iterator->destroy(iterator);
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
	iterator_t *iterator, *children;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	child_sa_t *child_sa;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
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
	iterator->destroy(iterator);
	pthread_mutex_unlock(&(this->mutex));
	
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

/**
 * Iterator hook for iterate, gets ike_sas instead of entries
 */
static hook_result_t iterator_hook(private_ike_sa_manager_t* this, entry_t *in,
								   ike_sa_t **out)
{
	/* check out entry */
	if (wait_for_entry(this, in))
	{
		*out = in->ike_sa;
		return HOOK_NEXT;
	}
	return HOOK_SKIP;
}

/**
 * Implementation of ike_sa_manager_t.create_iterator.
 */
static iterator_t *create_iterator(private_ike_sa_manager_t* this)
{
	iterator_t *iterator = this->ike_sa_list->create_iterator_locked(
											this->ike_sa_list, &this->mutex);
	
	/* register hook to iterator over ike_sas, not entries */
	iterator->set_iterator_hook(iterator, (iterator_hook_t*)iterator_hook, this);
	return iterator;
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
	charon->bus->set_sa(charon->bus, ike_sa);
	return retval;
}

/**
 * Implementation of ike_sa_manager_t.get_half_open_count.
 */
static int get_half_open_count(private_ike_sa_manager_t *this, host_t *ip)
{
	iterator_t *iterator;
	entry_t *entry;
	int count = 0;

	pthread_mutex_lock(&(this->mutex));
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		/* we check if we have a responder CONNECTING IKE_SA without checkout */
		if (!entry->ike_sa_id->is_initiator(entry->ike_sa_id) &&
			entry->ike_sa->get_state(entry->ike_sa) == IKE_CONNECTING)
		{
			/* if we have a host, we have wait until no other uses the IKE_SA */
			if (ip)
			{
				if (wait_for_entry(this, entry) && ip->ip_equals(ip, 
								entry->ike_sa->get_other_host(entry->ike_sa)))
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
	iterator->destroy(iterator);
	
	pthread_mutex_unlock(&(this->mutex));
	return count;
}

/**
 * Implementation of ike_sa_manager_t.destroy.
 */
static void destroy(private_ike_sa_manager_t *this)
{
	/* destroy all list entries */
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	entry_t *entry;
	
	pthread_mutex_lock(&(this->mutex));
	DBG2(DBG_MGR, "going to destroy IKE_SA manager and all managed IKE_SA's");
	/* Step 1: drive out all waiting threads  */
	DBG2(DBG_MGR, "set driveout flags for all stored IKE_SA's");
	iterator = list->create_iterator(list, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;	
	}
	DBG2(DBG_MGR, "wait for all threads to leave IKE_SA's");
	/* Step 2: wait until all are gone */
	iterator->reset(iterator);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		while (entry->waiting_threads)
		{
			/* wake up all */
			pthread_cond_broadcast(&(entry->condvar));
			/* go sleeping until they are gone */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
	}
	DBG2(DBG_MGR, "delete all IKE_SA's");
	/* Step 3: initiate deletion of all IKE_SAs */
	iterator->reset(iterator);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		entry->ike_sa->delete(entry->ike_sa);
	}
	iterator->destroy(iterator);
	
	DBG2(DBG_MGR, "destroy all entries");
	/* Step 4: destroy all entries */
	list->destroy_function(list, (void*)entry_destroy);
	pthread_mutex_unlock(&(this->mutex));
	
	this->randomizer->destroy(this->randomizer);
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
	this->public.destroy = (void(*)(ike_sa_manager_t*))destroy;
	this->public.checkout = (ike_sa_t*(*)(ike_sa_manager_t*, ike_sa_id_t*))checkout;
	this->public.checkout_new = (ike_sa_t*(*)(ike_sa_manager_t*,bool))checkout_new;
	this->public.checkout_by_message = (ike_sa_t*(*)(ike_sa_manager_t*,message_t*))checkout_by_message;
	this->public.checkout_by_peer = (ike_sa_t*(*)(ike_sa_manager_t*,host_t*,host_t*,identification_t*,identification_t*))checkout_by_peer;
	this->public.checkout_by_id = (ike_sa_t*(*)(ike_sa_manager_t*,u_int32_t,bool))checkout_by_id;
	this->public.checkout_by_name = (ike_sa_t*(*)(ike_sa_manager_t*,char*,bool))checkout_by_name;
	this->public.create_iterator = (iterator_t*(*)(ike_sa_manager_t*))create_iterator;
	this->public.checkin = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin;
	this->public.checkin_and_destroy = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin_and_destroy;
	this->public.get_half_open_count = (int(*)(ike_sa_manager_t*,host_t*))get_half_open_count;
	
	/* initialize private variables */
	this->ike_sa_list = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	this->randomizer = randomizer_create();
	this->hasher = hasher_create(HASH_SHA1);
	
	return &this->public;
}
