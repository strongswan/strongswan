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
#include <utils/logger.h>
#include <utils/logger_manager.h>
#include <utils/linked_list.h>

typedef struct ike_sa_entry_t ike_sa_entry_t;

/**
 * An entry in the linked list, contains IKE_SA, locking and lookup data.
 */
struct ike_sa_entry_t {
	/**
	 * Destructor, also destroys associated ike_sa_t object.
	 */
	status_t (*destroy) (ike_sa_entry_t *this);
	
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
};

/**
 * Implementation of ike_sa_entry_t.destroy.
 */
static status_t ike_sa_entry_destroy(ike_sa_entry_t *this)
{
	/* also destroy IKE SA */
	this->ike_sa->destroy(this->ike_sa);
	this->ike_sa_id->destroy(this->ike_sa_id);
	free(this);
	return SUCCESS;
}

/**
 * @brief Creates a new entry for the ike_sa_t list.
 *
 * This constructor additionaly creates a new and empty SA.
 *
 * @param ike_sa_id		The associated ike_sa_id_t, will be cloned
 * @return				ike_sa_entry_t object
 */
static ike_sa_entry_t *ike_sa_entry_create(ike_sa_id_t *ike_sa_id)
{
	ike_sa_entry_t *this = malloc_thing(ike_sa_entry_t);

	/* destroy function */
	this->destroy = ike_sa_entry_destroy;
	
	this->waiting_threads = 0;
	pthread_cond_init(&(this->condvar), NULL);
	
	/* we set checkout flag when we really give it out */
	this->checked_out = FALSE;
	this->driveout_new_threads = FALSE;
	this->driveout_waiting_threads = FALSE;
	
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
	  * Logger used for this IKE SA Manager.
	  */
	 logger_t *logger;

	 /**
	  * Linked list with entries for the ike_sa_t objects.
	  */
	 linked_list_t *ike_sa_list;
	 
	 /**
	  * A randomizer, to get random SPIs for our side
	  */
	 randomizer_t *randomizer;
};

/**
 * Implementation of private_ike_sa_manager_t.get_entry_by_id.
 */
static status_t get_entry_by_id(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_entry_t **entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	status_t status;
	
	/* create iterator over list of ike_sa's */
	iterator = list->create_iterator(list, TRUE);

	/* default status */
	status = NOT_FOUND;
	
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		
		iterator->current(iterator, (void**)&current);
		if (current->ike_sa_id->get_responder_spi(current->ike_sa_id) == 0)
		{
			/* seems to be a half ready ike_sa */
			if ((current->ike_sa_id->get_initiator_spi(current->ike_sa_id) ==
						  ike_sa_id->get_initiator_spi(ike_sa_id)) &&
				(ike_sa_id->is_initiator(ike_sa_id) == 
						  current->ike_sa_id->is_initiator(current->ike_sa_id)))
			{
		 		this->logger->log(this->logger, CONTROL|LEVEL2, 
								  "found entry by initiator spi %d",
								  ike_sa_id->get_initiator_spi(ike_sa_id));
				*entry = current;
				status = SUCCESS;
				break;
			}
		}
		else if (ike_sa_id->get_responder_spi(ike_sa_id) == 0)
		{
			if ((current->ike_sa_id->get_initiator_spi(current->ike_sa_id) == 
						  ike_sa_id->get_initiator_spi(ike_sa_id)) &&
				(ike_sa_id->is_initiator(ike_sa_id) == 
						  current->ike_sa_id->is_initiator(current->ike_sa_id)))
			{
		 		this->logger->log(this->logger, CONTROL|LEVEL2, "found entry by initiator spi %d",
								  ike_sa_id->get_initiator_spi(ike_sa_id));
				*entry = current;
				status = SUCCESS;
				break;
			}			
		}
		if (current->ike_sa_id->equals(current->ike_sa_id, ike_sa_id))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "found entry by full ID");
			*entry = current;
			status = SUCCESS;
			break;
		}
	}
	
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of private_ike_sa_manager_t.get_entry_by_sa.
 */
static status_t get_entry_by_sa(private_ike_sa_manager_t *this, ike_sa_t *ike_sa, ike_sa_entry_t **entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	status_t status;
	
	iterator = list->create_iterator(list, TRUE);
	
	/* default status */
	status = NOT_FOUND;
	
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		iterator->current(iterator, (void**)&current);
		/* only pointers are compared */
		if (current->ike_sa == ike_sa)
		{
	 		this->logger->log(this->logger, CONTROL|LEVEL2, "found entry by pointer");
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
static status_t delete_entry(private_ike_sa_manager_t *this, ike_sa_entry_t *entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	status_t status;
	
	iterator = list->create_iterator(list, TRUE);

	status = NOT_FOUND;
	
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		iterator->current(iterator, (void**)&current);
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
			
	 		this->logger->log(this->logger, CONTROL|LEVEL2, 
							  "found entry by pointer. Going to delete it");
			iterator->remove(iterator);
			entry->destroy(entry);
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
static bool wait_for_entry(private_ike_sa_manager_t *this, ike_sa_entry_t *entry)
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
	
	this->randomizer->get_pseudo_random_bytes(this->randomizer, 8, (u_int8_t*)&spi);
	
	return spi;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_id.
 */
static ike_sa_t* checkout_by_id(private_ike_sa_manager_t *this,
								   host_t *my_host,
								   host_t *other_host,
								   identification_t *my_id,
								   identification_t *other_id)
{
	iterator_t *iterator;
	ike_sa_t *ike_sa = NULL;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		identification_t *found_my_id, *found_other_id;
		host_t *found_my_host, *found_other_host;
		int wc;
		
		iterator->current(iterator, (void**)&entry);
		if (!wait_for_entry(this, entry))
		{
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
			this->logger->log(this->logger, CONTROL|LEVEL1, 
							  "found an existing IKE_SA for %s[%s]...%s[%s]",
							  my_host->get_string(my_host), other_host->get_string(other_host),
							  my_id->get_string(my_id), other_id->get_string(other_id));
			entry->checked_out = TRUE;
			ike_sa = entry->ike_sa;
		}
	}
	iterator->destroy(iterator);
	
	if (!ike_sa)
	{
		u_int64_t initiator_spi;
		ike_sa_entry_t *new_ike_sa_entry;
		ike_sa_id_t *new_ike_sa_id;
		
		initiator_spi = get_next_spi(this);
		new_ike_sa_id = ike_sa_id_create(0, 0, TRUE);
		new_ike_sa_id->set_initiator_spi(new_ike_sa_id, initiator_spi);
		
		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(new_ike_sa_id);
		this->logger->log(this->logger, CONTROL|LEVEL2,
						  "created IKE_SA %llx:%llx, role %s",
						  new_ike_sa_id->get_initiator_spi(new_ike_sa_id),
						  new_ike_sa_id->get_responder_spi(new_ike_sa_id),
						  new_ike_sa_id->is_initiator(new_ike_sa_id) ? "initiator" : "responder");
		new_ike_sa_id->destroy(new_ike_sa_id);
		
		this->ike_sa_list->insert_last(this->ike_sa_list, new_ike_sa_entry);
		
		/* check ike_sa out */
		this->logger->log(this->logger, CONTROL|LEVEL1, 
						  "new IKE_SA created for IDs %s - %s",
						  my_id->get_string(my_id), other_id->get_string(other_id));
		new_ike_sa_entry->checked_out = TRUE;
		ike_sa = new_ike_sa_entry->ike_sa;
	}
	pthread_mutex_unlock(&(this->mutex));
	
	return ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout.
 */
static ike_sa_t* checkout(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id)
{
	bool responder_spi_set;
	bool initiator_spi_set;
	bool original_initiator;
	ike_sa_t *ike_sa = NULL;
	
	this->logger->log(this->logger, CONTROL|LEVEL2,
					  "checkout IKE_SA %llx:%llx, role %s",
					  ike_sa_id->get_initiator_spi(ike_sa_id),
					  ike_sa_id->get_responder_spi(ike_sa_id),
					  ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "%d IKE_SAs in manager",
					  this->ike_sa_list->get_count(this->ike_sa_list));
	
	/* each access is locked */
	pthread_mutex_lock(&(this->mutex));
	
	responder_spi_set = ike_sa_id->get_responder_spi(ike_sa_id);
	initiator_spi_set = ike_sa_id->get_initiator_spi(ike_sa_id);
	original_initiator = ike_sa_id->is_initiator(ike_sa_id);
	
	if ((initiator_spi_set && responder_spi_set) ||
		((initiator_spi_set && !responder_spi_set) && (original_initiator)))
	{
		/* we SHOULD have an IKE_SA for these SPIs in the list,
		 * if not, we can't handle the request...
		 */
		ike_sa_entry_t *entry;
		/* look for the entry */
		if (get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
		{
			if (wait_for_entry(this, entry))
			{
				this->logger->log(this->logger, CONTROL|LEVEL2, 
								  "IKE_SA successfully checked out");
				/* ok, this IKE_SA is finally ours */
				entry->checked_out = TRUE;
				ike_sa = entry->ike_sa;
			}
			else
			{
				this->logger->log(this->logger, CONTROL|LEVEL2, 
								  "IKE_SA found, but not allowed to check it out");
			}
		}
		else
		{
			this->logger->log(this->logger, ERROR|LEVEL1, 
							  "IKE_SA not stored in list");
			/* looks like there is no such IKE_SA, better luck next time... */
		}
	}
	else if ((initiator_spi_set && !responder_spi_set) && (!original_initiator))
	{
		/* an IKE_SA_INIT from an another endpoint,
		 * he is the initiator.
		 * For simplicity, we do NOT check for retransmitted
		 * IKE_SA_INIT-Requests here, so EVERY single IKE_SA_INIT-
		 * Request (even a retransmitted one) will result in a
		 * IKE_SA. This could be improved...
		 */
		u_int64_t responder_spi;
		ike_sa_entry_t *new_ike_sa_entry;
		
		/* set SPIs, we are the responder */
		responder_spi = get_next_spi(this);
		
		/* we also set arguments spi, so its still valid */
		ike_sa_id->set_responder_spi(ike_sa_id, responder_spi);
		
		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(ike_sa_id);
		
		this->ike_sa_list->insert_last(this->ike_sa_list, new_ike_sa_entry);
		
		/* check ike_sa out */
		this->logger->log(this->logger, CONTROL|LEVEL1,
						  "IKE_SA added to list of known IKE_SAs");
		new_ike_sa_entry->checked_out = TRUE;
		ike_sa = new_ike_sa_entry->ike_sa;
	}
	else if (!initiator_spi_set && !responder_spi_set && original_initiator)
	{
		/* checkout of a new and unused IKE_SA, used for rekeying */
		ike_sa_entry_t *new_ike_sa_entry;
		
		ike_sa_id->set_initiator_spi(ike_sa_id, get_next_spi(this));
		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(ike_sa_id);
		this->logger->log(this->logger, CONTROL|LEVEL2,
							"created IKE_SA %llx:%llx, role %s",
							ike_sa_id->get_initiator_spi(ike_sa_id),
							ike_sa_id->get_responder_spi(ike_sa_id),
							ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
			
		this->ike_sa_list->insert_last(this->ike_sa_list, new_ike_sa_entry);
		
		/* check ike_sa out */
		new_ike_sa_entry->checked_out = TRUE;
		ike_sa = new_ike_sa_entry->ike_sa;
	}
	else
	{
		/* responder set, initiator not: here is something seriously wrong! */
 		this->logger->log(this->logger, ERROR|LEVEL1, "invalid IKE_SA SPIs");
	}
	
	pthread_mutex_unlock(&(this->mutex));
	return ike_sa;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_child.
 */
static ike_sa_t* checkout_by_child(private_ike_sa_manager_t *this,
								   u_int32_t reqid)
{
	iterator_t *iterator;
	ike_sa_t *ike_sa = NULL;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		
		iterator->current(iterator, (void**)&entry);
		if (wait_for_entry(this, entry))
		{
			/* ok, access is exclusive for us, check for child */
			if (entry->ike_sa->has_child_sa(entry->ike_sa, reqid))
			{
				/* match */
				entry->checked_out = TRUE;
				ike_sa = entry->ike_sa;
				break;
			}
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&(this->mutex));
	
	return ike_sa;
}

/**
 * Implementation of ike_sa_manager_t.get_ike_sa_list.
 */
static linked_list_t *get_ike_sa_list(private_ike_sa_manager_t* this)
{
	linked_list_t *list;
	iterator_t *iterator;
	
	pthread_mutex_lock(&(this->mutex));
	
	list = linked_list_create();
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		iterator->current(iterator, (void**)&entry);
		list->insert_last(list, (void*)entry->ike_sa_id->clone(entry->ike_sa_id));
	}
	iterator->destroy(iterator);
	
	pthread_mutex_unlock(&(this->mutex));
	return list;
}

/**
 * Implementation of ike_sa_manager_t.log_status.
 */
static void log_status(private_ike_sa_manager_t* this, logger_t* logger, char* name)
{
	iterator_t *iterator;
	u_int instances;
	
	pthread_mutex_lock(&(this->mutex));
	
	instances = this->ike_sa_list->get_count(this->ike_sa_list);
	if (instances)
	{
		logger->log(logger, CONTROL, "Instances (%d):", instances);
	}
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		
		iterator->current(iterator, (void**)&entry);
		if (wait_for_entry(this, entry))
		{
			entry->ike_sa->log_status(entry->ike_sa, logger, name);
		}
	}
	iterator->destroy(iterator);
	
	pthread_mutex_unlock(&(this->mutex));
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
	ike_sa_entry_t *entry;
	ike_sa_id_t *ike_sa_id;
	
	ike_sa_id = ike_sa->get_id(ike_sa);
	
	this->logger->log(this->logger, CONTROL|LEVEL2,
					   "checkin IKE_SA %llx:%llx, role %s",
					  ike_sa_id->get_initiator_spi(ike_sa_id),
					  ike_sa_id->get_responder_spi(ike_sa_id),
					  ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	
	pthread_mutex_lock(&(this->mutex));

	/* look for the entry */
	if (get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* ike_sa_id must be updated */
		entry->ike_sa_id->replace_values(entry->ike_sa_id, ike_sa->get_id(ike_sa));
		/* signal waiting threads */
		entry->checked_out = FALSE;
		this->logger->log(this->logger, CONTROL|LEVEL1, "check-in of IKE_SA successful.");
		pthread_cond_signal(&(entry->condvar));
	 	retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger, ERROR, 
						  "tried to check in nonexisting IKE_SA");
		/* this SA is no more, this REALLY should not happen */
		retval = NOT_FOUND;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "%d IKE_SAs in manager now",
				this->ike_sa_list->get_count(this->ike_sa_list));
	pthread_mutex_unlock(&(this->mutex));
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
	ike_sa_entry_t *entry;
	status_t retval;
	ike_sa_id_t *ike_sa_id;
	
	ike_sa_id = ike_sa->get_id(ike_sa);
	this->logger->log(this->logger, CONTROL|LEVEL2,
					  "checkin and destroy IKE_SA %llx:%llx, role %s",
					  ike_sa_id->get_initiator_spi(ike_sa_id),
					  ike_sa_id->get_responder_spi(ike_sa_id),
					  ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");

	pthread_mutex_lock(&(this->mutex));

	if (get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* drive out waiting threads, as we are in hurry */
		entry->driveout_waiting_threads = TRUE;
		
		delete_entry(this, entry);
		
		this->logger->log(this->logger, CONTROL|LEVEL1, 
						  "check-in and destroy of IKE_SA successful");
		retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR, 
						  "tried to check-in and delete nonexisting IKE_SA");
		retval = NOT_FOUND;
	}
	
	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

/**
 * Implementation of ike_sa_manager_t.delete.
 */
static status_t delete_(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id)
{
	/* deletion is a bit complex, we must garant that no thread is waiting for
	 * this SA.
	 * We take this SA from the list, and start signaling while threads
	 * are in the condvar.
	 */
	ike_sa_entry_t *entry;
	status_t retval;
	
	this->logger->log(this->logger, CONTROL|LEVEL2,
					  "delete IKE_SA %llx:%llx, role %s",
					  ike_sa_id->get_initiator_spi(ike_sa_id),
					  ike_sa_id->get_responder_spi(ike_sa_id),
					  ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	
	pthread_mutex_lock(&(this->mutex));
	
	if (get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
	{
		/* we try a delete. If it succeeds, our job is done here. The
		 * other peer will reply, and the IKE SA gets the finally deleted...
		 */
		if (entry->ike_sa->delete(entry->ike_sa) == SUCCESS)
		{
			this->logger->log(this->logger, CONTROL|LEVEL1,
							  "initiated delete for IKE_SA");
		}
		/* but if the IKE SA is not in a state where the deletion is 
		 * negotiated with the other peer, we can destroy the IKE SA on our own. 
		 */
		else
		{
			
		}
		retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR|LEVEL1,
						  "tried to delete nonexisting IKE_SA");
		retval = NOT_FOUND;
	}

	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

/**
 * Implementation of ike_sa_manager_t.delete_by_name.
 */
static status_t delete_by_name(private_ike_sa_manager_t *this, char *name)
{
	iterator_t *iterator;
	iterator_t *child_iter;
	ike_sa_entry_t *entry;
	size_t name_len = strlen(name);
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->iterate(iterator, (void**)&entry))
	{
		if (wait_for_entry(this, entry))
		{
			/* delete ike_sa if:
			 * name{x} matches completely
			 * name{} matches by name
			 * name matches by name
			 */
			bool del = FALSE;
			char *ike_name;
			char *child_name;
			child_sa_t *child_sa;
			
			ike_name = entry->ike_sa->get_name(entry->ike_sa);
			/* check if "name{x}" matches completely */
			if (strcmp(name, ike_name) == 0)
			{
				del = TRUE;
			}
			/* check if name is in form of "name{}" and matches to ike_name */
			else if (name_len > 1 &&
					 name[name_len - 2] == '{' && name[name_len - 1] == '}' &&
					 strlen(ike_name) > name_len &&
					 ike_name[name_len - 2] == '{' &&
					 strncmp(name, ike_name, name_len - 2) == 0)
			{
				del = TRUE;
			}
			/* finally, check if name is "name" and matches ike_name */
			else if (name_len == strchr(ike_name, '{') - ike_name &&
					 strncmp(name, ike_name, name_len) == 0)
			{
				del = TRUE;
			}
			
			if (del)
			{
				if (entry->ike_sa->delete(entry->ike_sa) == DESTROY_ME)
				{
					delete_entry(this, entry);
					iterator->reset(iterator);
				}
				/* no need to check children, as we delete all */
				continue;
			}
			
			/* and now the same game for all children. delete child_sa if:
			 * name[x] matches completely
			 * name[] matches by name
			 * name matches by name
			 */
			child_iter = entry->ike_sa->create_child_sa_iterator(entry->ike_sa);
			while (child_iter->iterate(child_iter, (void**)&child_sa))
			{
				/* skip ROUTED children, they have their "unroute" command */
				if (child_sa->get_state(child_sa) == CHILD_ROUTED)
				{
					continue;
				}
				
				child_name = child_sa->get_name(child_sa);
				del = FALSE;
				/* check if "name[x]" matches completely */
				if (strcmp(name, child_name) == 0)
				{
					del = TRUE;
				}
				/* check if name is in form of "name[]" and matches to child_name */
				else if (name_len > 1 &&
						 name[name_len - 2] == '[' && name[name_len - 1] == ']' &&
						 strlen(child_name) > name_len &&
						 child_name[name_len - 2] == '[' &&
						 strncmp(name, child_name, name_len - 2) == 0)
				{
					del = TRUE;
				}
				/* finally, check if name is "name" and matches child_name */
				else if (name_len == strchr(child_name, '[') - child_name &&
						 strncmp(name, child_name, name_len) == 0)
				{
					del = TRUE;
				}
				if (del)
				{
					if (entry->ike_sa->delete_child_sa(entry->ike_sa,
						child_sa->get_protocol(child_sa),
						child_sa->get_spi(child_sa, TRUE)) == DESTROY_ME)
					{
						/* when a fatal error occurs, we are responsible to
						 * remove the IKE_SA */
						delete_entry(this, entry);
						iterator->reset(iterator);
						break;
					}
				}
			}
			child_iter->destroy(child_iter);
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&(this->mutex));
	
	return SUCCESS;
}

/**
 * Implementation of ike_sa_manager_t.destroy.
 */
static void destroy(private_ike_sa_manager_t *this)
{
	/* destroy all list entries */
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	ike_sa_entry_t *entry;
	
	pthread_mutex_lock(&(this->mutex));
	this->logger->log(this->logger, CONTROL|LEVEL1, 
					  "going to destroy IKE_SA manager and all managed IKE_SA's");
	/* Step 1: drive out all waiting threads  */
	this->logger->log(this->logger, CONTROL|LEVEL2, 
					  "set driveout flags for all stored IKE_SA's");
	iterator = list->create_iterator(list, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;	
	}
	this->logger->log(this->logger, CONTROL|LEVEL2, 
					  "wait for all threads to leave IKE_SA's");
	/* Step 2: wait until all are gone */
	iterator->reset(iterator);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		while (entry->waiting_threads)
		{
			/* wake up all */
			pthread_cond_broadcast(&(entry->condvar));
			/* go sleeping until they are gone */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
	}
	this->logger->log(this->logger, CONTROL|LEVEL2, "delete all IKE_SA's");
	/* Step 3: initiate deletion of all IKE_SAs */
	iterator->reset(iterator);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		entry->ike_sa->delete(entry->ike_sa);
	}
	iterator->destroy(iterator);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "destroy all entries");
	/* Step 4: destroy all entries */
	while (list->remove_last(list, (void**)&entry) == SUCCESS)
	{
		entry->destroy(entry);
	}
	list->destroy(list);
	pthread_mutex_unlock(&(this->mutex));
	
	this->randomizer->destroy(this->randomizer);
	
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
	this->public.checkout_by_id = (ike_sa_t*(*)(ike_sa_manager_t*,host_t*,host_t*,identification_t*,identification_t*))checkout_by_id;
	this->public.checkout = (ike_sa_t*(*)(ike_sa_manager_t*, ike_sa_id_t*))checkout;
	this->public.checkout_by_child = (ike_sa_t*(*)(ike_sa_manager_t*,u_int32_t))checkout_by_child;
	this->public.get_ike_sa_list = (linked_list_t*(*)(ike_sa_manager_t*))get_ike_sa_list;
	this->public.log_status = (void(*)(ike_sa_manager_t*,logger_t*,char*))log_status;
	this->public.checkin = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin;
	this->public.delete = (status_t(*)(ike_sa_manager_t*,ike_sa_id_t*))delete_;
	this->public.delete_by_name = (status_t(*)(ike_sa_manager_t*,char*))delete_by_name;
	this->public.checkin_and_destroy = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin_and_destroy;

	/* initialize private variables */
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA_MANAGER);
	
	this->ike_sa_list = linked_list_create();

	pthread_mutex_init(&(this->mutex), NULL);

	this->randomizer = randomizer_create();

	return (ike_sa_manager_t*)this;
}
