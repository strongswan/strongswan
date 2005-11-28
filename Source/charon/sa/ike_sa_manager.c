/**
 * @file ike_sa_manager.c
 *
 * @brief Central point for managing IKE-SAs (creation, locking, deleting...)
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

#include <pthread.h>
#include <string.h>

#include "ike_sa_manager.h"

#include <globals.h>
#include <sa/ike_sa_id.h>
#include <utils/allocator.h>
#include <utils/logger.h>
#include <utils/logger_manager.h>
#include <utils/linked_list.h>

typedef struct ike_sa_entry_t ike_sa_entry_t;

/**
 * @brief An entry in the linked list, contains IKE_SA, locking and lookup data.
 */
struct ike_sa_entry_t {
	/**
	 * destructor, also destroys ike_sa
	 */
	status_t (*destroy) (ike_sa_entry_t *this);
	/**
	 * Number of threads waiting for this ike_sa
	 */
	int waiting_threads;
	/**
	 * condvar where threads can wait until it's free again
	 */
	pthread_cond_t condvar;
	/**
	 * is this ike_sa currently checked out?
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
	 * identifiaction of ike_sa (SPIs)
	 */
	ike_sa_id_t *ike_sa_id;
	/**
	 * the contained ike_sa
	 */
	ike_sa_t *ike_sa;
};

/**
 * @see ike_sa_entry_t.destroy
 */
static status_t ike_sa_entry_destroy(ike_sa_entry_t *this)
{
	/* also destroy IKE SA */
	this->ike_sa->destroy(this->ike_sa);
	this->ike_sa_id->destroy(this->ike_sa_id);
	allocator_free(this);
	return SUCCESS;
}

/**
 * @brief creates a new entry for the ike_sa list
 *
 * This constructor additionaly creates a new and empty SA
 *
 * @param ike_sa_id		the associated ike_sa_id_t, will be cloned
 * @return				created entry, with ike_sa and ike_sa_id
 */
static ike_sa_entry_t *ike_sa_entry_create(ike_sa_id_t *ike_sa_id)
{
	ike_sa_entry_t *this = allocator_alloc_thing(ike_sa_entry_t);

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
 * Additional private members to ike_sa_manager_t
 */
struct private_ike_sa_manager_t {
	/**
	 * Public members
	 */
	 ike_sa_manager_t public;

	/**
	 * @brief get next spi
	 *
	 * we give out SPIs incremental
	 *
	 * @param this			the ike_sa_manager
	 * @return 				the next spi
	 */
	u_int64_t (*get_next_spi) (private_ike_sa_manager_t *this);

	/**
	 * @brief find the ike_sa_entry in the list by SPIs
	 *
	 * This function simply iterates over the linked list. A hash-table
	 * would be more efficient when storing a lot of IKE_SAs...
	 *
	 * @param this			the ike_sa_manager containing the list
	 * @param ike_sa_id		id of the ike_sa, containing SPIs
	 * @param entry[out]	pointer to set to the found entry
	 * @return				
	 * 						- SUCCESS when found,
	 * 						- NOT_FOUND when no such ike_sa_id in list
	 */
	 status_t (*get_entry_by_id) (private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_entry_t **entry);

	 /**
	 * @brief find the ike_sa_entry in the list by pointer to SA.
	 *
	 * This function simply iterates over the linked list. A hash-table
	 * would be more efficient when storing a lot of IKE_SAs...
	 *
	 * @param this			the ike_sa_manager containing the list
	 * @param ike_sa			pointer to the ike_sa
	 * @param entry[out]		pointer to set to the found entry
	 * @return				
	 * 						- SUCCESS when found,
	 * 						- NOT_FOUND when no such ike_sa_id in list
	 */
	 status_t (*get_entry_by_sa) (private_ike_sa_manager_t *this, ike_sa_t *ike_sa, ike_sa_entry_t **entry);
	 
	 /**
	  * @brief delete an entry from the linked list
	  *
	  * @param this		the ike_sa_manager containing the list
	  * @param entry		entry to delete
	  * @return				
	  * 					- SUCCESS when found,
	  * 					- NOT_FOUND when no such ike_sa_id in list
	  */
	 status_t (*delete_entry) (private_ike_sa_manager_t *this, ike_sa_entry_t *entry);

	 /**
	  * lock for exclusivly accessing the manager
	  */
	 pthread_mutex_t mutex;

	 /**
	  * Logger used for this IKE SA Manager
	  */
	 logger_t *logger;

	 /**
	  * Linked list with entries for the ike_sa
	  */
	 linked_list_t *ike_sa_list;
	 
	 /**
	  * Next SPI, needed for incremental creation of SPIs
	  */
	 u_int64_t next_spi;
};


/**
 * Implements private_ike_sa_manager_t.get_entry_by_id.
 */
static status_t get_entry_by_id(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_entry_t **entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	status_t status;
	
	/* create iterator over list of ike_sa's */
	list->create_iterator(list, &iterator, TRUE);

	/* default status */
	status = NOT_FOUND;
	
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		
		iterator->current(iterator, (void**)&current);
		if (current->ike_sa_id->get_responder_spi(current->ike_sa_id) == 0) {
			/* seems to be a half ready ike_sa */
			if ((current->ike_sa_id->get_initiator_spi(current->ike_sa_id) == ike_sa_id->get_initiator_spi(ike_sa_id))
				&& (ike_sa_id->is_initiator(ike_sa_id) == current->ike_sa_id->is_initiator(current->ike_sa_id)))
			{
		 		this->logger->log(this->logger,CONTROL | MOST,"Found entry by initiator spi %d",ike_sa_id->get_initiator_spi(ike_sa_id));
				*entry = current;
				status = SUCCESS;
				break;
			}
		}
		 if (current->ike_sa_id->equals(current->ike_sa_id, ike_sa_id))
		{
			this->logger->log(this->logger,CONTROL | MOST,"Found entry by full ID");
			*entry = current;
			status = SUCCESS;
			break;
		}
	}
	
	iterator->destroy(iterator);
	return status;
}

/**
 * Implements private_ike_sa_manager_t.get_entry_by_sa.
 */
static status_t get_entry_by_sa(private_ike_sa_manager_t *this, ike_sa_t *ike_sa, ike_sa_entry_t **entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	status_t status;
	
	list->create_iterator(list, &iterator, TRUE);
	
	/* default status */
	status = NOT_FOUND;
	
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		iterator->current(iterator, (void**)&current);
		/* only pointers are compared */
		if (current->ike_sa == ike_sa)
		{
	 		this->logger->log(this->logger,CONTROL | MOST,"Found entry by pointer");
			*entry = current;
			status = SUCCESS;
			break;
		}
	}
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implements private_ike_sa_manager_s.delete_entry.
 */
static status_t delete_entry(private_ike_sa_manager_t *this, ike_sa_entry_t *entry)
{
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	status_t status;
	
	list->create_iterator(list, &iterator, TRUE);

	status = NOT_FOUND;	
	
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		iterator->current(iterator, (void**)&current);
		if (current == entry) 
		{
	 		this->logger->log(this->logger,CONTROL | MOST,"Found entry by pointer. Going to delete it.");
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
 * Implements private_ike_sa_manager_t.get_next_spi.
 */
static u_int64_t get_next_spi(private_ike_sa_manager_t *this)
{
	this->next_spi++;
	if (this->next_spi == 0) {
		/* TODO handle overflow,
		 * delete all SAs or so
		 */
	}
	return this->next_spi;
}

/**
 * Implementation of ike_sa_manager.create_and_checkout.
 */
static void create_and_checkout(private_ike_sa_manager_t *this,ike_sa_t **ike_sa)
{
	u_int64_t initiator_spi;
	ike_sa_entry_t *new_ike_sa_entry;
	ike_sa_id_t *new_ike_sa_id;

	initiator_spi = this->get_next_spi(this);
	new_ike_sa_id = ike_sa_id_create(0, 0, TRUE);
	new_ike_sa_id->set_initiator_spi(new_ike_sa_id, initiator_spi);

	/* create entry */
	new_ike_sa_entry = ike_sa_entry_create(new_ike_sa_id);
	new_ike_sa_id->destroy(new_ike_sa_id);

	/* each access is locked */
	pthread_mutex_lock(&(this->mutex));
	
	this->ike_sa_list->insert_last(this->ike_sa_list, new_ike_sa_entry);

	/* check ike_sa out */
	this->logger->log(this->logger,CONTROL | MORE ,"New IKE_SA created and added to list of known IKE_SA's");
	new_ike_sa_entry->checked_out = TRUE;
	*ike_sa = new_ike_sa_entry->ike_sa;

	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of ike_sa_manager.checkout.
 */
static status_t checkout(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_t **ike_sa)
{
	bool responder_spi_set;
	bool initiator_spi_set;
	status_t retval;
	
	/* each access is locked */
	pthread_mutex_lock(&(this->mutex));
	
	responder_spi_set = (FALSE != ike_sa_id->get_responder_spi(ike_sa_id));
	initiator_spi_set = (FALSE != ike_sa_id->get_initiator_spi(ike_sa_id));
	
	if (initiator_spi_set && responder_spi_set)
	{
		/* we SHOULD have an IKE_SA for these SPIs in the list,
		 * if not, we can't handle the request...
		 */
		 ike_sa_entry_t *entry;
		 /* look for the entry */
		 if (this->get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
		 {
		 	/* can we give this ike_sa out to new requesters?*/
		 	if (entry->driveout_new_threads)
		 	{
		 		this->logger->log(this->logger,CONTROL|MORE,"Drive out new thread for existing IKE_SA");
		 		/* no we can't */
		 		retval = NOT_FOUND;
		 	}
		 	else
		 	{
				/* is this IKE_SA already checked out ?? 
				 * are we welcome to get this SA ? */
				while (entry->checked_out && !entry->driveout_waiting_threads)	
				{ 
					/* so wait until we can get it for us.
					 * we register us as waiting.
					 */
					entry->waiting_threads++;
					pthread_cond_wait(&(entry->condvar), &(this->mutex));
					entry->waiting_threads--;
				}
				
				/* hm, a deletion request forbids us to get this SA, go home */
				if (entry->driveout_waiting_threads)
				{
					/* we must signal here, others are interested that we leave */
					pthread_cond_signal(&(entry->condvar));
					this->logger->log(this->logger,CONTROL|MORE,"Drive out waiting thread for existing IKE_SA");
					retval = NOT_FOUND;
				}
				else
				{
					this->logger->log(this->logger,CONTROL|MOST,"IKE SA successfully checked out");
					/* ok, this IKE_SA is finally ours */
					entry->checked_out = TRUE;
					*ike_sa = entry->ike_sa;
					/* DON'T use return, we must unlock the mutex! */
					retval = SUCCESS; 
				}
			}
		}
		else
		{
			this->logger->log(this->logger,ERROR | MORE,"IKE SA not stored in known IKE_SA list");
			/* looks like there is no such IKE_SA, better luck next time... */
			/* DON'T use return, we must unlock the mutex! */
			retval = NOT_FOUND;
		}
	}
	else if (initiator_spi_set && !responder_spi_set)
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
		responder_spi = this->get_next_spi(this);
		
		/* we also set arguments spi, so its still valid */
		ike_sa_id->set_responder_spi(ike_sa_id, responder_spi);
		
		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(ike_sa_id);
		
		this->ike_sa_list->insert_last(this->ike_sa_list, new_ike_sa_entry);
		
		/* check ike_sa out */
		this->logger->log(this->logger,CONTROL | MORE ,"IKE_SA added to list of known IKE_SA's");
		new_ike_sa_entry->checked_out = TRUE;
		*ike_sa = new_ike_sa_entry->ike_sa;
		
		retval = SUCCESS;
	}
	else
	{
		/* responder set, initiator not: here is something seriously wrong! */
 		this->logger->log(this->logger,ERROR | MORE, "Invalid IKE_SA SPI's");
		/* DON'T use return, we must unlock the mutex! */
		retval = INVALID_ARG;
	}

	pthread_mutex_unlock(&(this->mutex));
	/* OK, unlocked... */
	return retval;
}

/**
 * Implements ike_sa_manager_t-function checkin.
 * @see ike_sa_manager_t.checkin.
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
	
	pthread_mutex_lock(&(this->mutex));

	/* look for the entry */
	if (this->get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* ike_sa_id must be updated */
		entry->ike_sa_id->replace_values(entry->ike_sa_id, ike_sa->get_id(ike_sa));
		/* signal waiting threads */
		entry->checked_out = FALSE;
		this->logger->log(this->logger,CONTROL | MORE,"Checkin of IKE_SA successful.");
		pthread_cond_signal(&(entry->condvar));
	 	retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR,"Fatal Error: Tried to checkin nonexisting IKE_SA");
		/* this SA is no more, this REALLY should not happen */
		retval = NOT_FOUND;
	}
	pthread_mutex_unlock(&(this->mutex));
	return retval;
}


/**
 * Implements ike_sa_manager_t-function checkin_and_delete.
 * @see ike_sa_manager_t.checkin_and_delete.
 */
static status_t checkin_and_delete(private_ike_sa_manager_t *this, ike_sa_t *ike_sa)
{
	/* deletion is a bit complex, we must garant that no thread is waiting for
	 * this SA.
	 * We take this SA from the list, and start signaling while threads
	 * are in the condvar.
	 */
	ike_sa_entry_t *entry;
	status_t retval;

	pthread_mutex_lock(&(this->mutex));

	if (this->get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* mark it, so now new threads can acquire this SA */
		entry->driveout_new_threads = TRUE;
		/* additionaly, drive out waiting threads */
		entry->driveout_waiting_threads = TRUE;

		/* wait until all workers have done their work */
		while (entry->waiting_threads > 0)
		{
			/* let the other threads do some work*/
			pthread_cond_signal(&(entry->condvar));
			/* and the nice thing, they will wake us again when their work is done */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
		/* ok, we are alone now, no threads waiting in the entry's condvar */
		this->delete_entry(this, entry);
		this->logger->log(this->logger,CONTROL | MORE,"Checkin and delete of IKE_SA successful");
		retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR,"Fatal Error: Tried to checkin and delete nonexisting IKE_SA");
		retval = NOT_FOUND;
	}
	
	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

/**
 * Implements ike_sa_manager_t.delete.
 */
static status_t delete(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id)
{
	/* deletion is a bit complex, we must garant that no thread is waiting for
	 * this SA.
	 * We take this SA from the list, and start signaling while threads
	 * are in the condvar.
	 */
	ike_sa_entry_t *entry;
	status_t retval;

	pthread_mutex_lock(&(this->mutex));

	if (this->get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
	{
		/* mark it, so now new threads can acquire this SA */
		entry->driveout_new_threads = TRUE;

		/* wait until all workers have done their work */
		while (entry->waiting_threads)
		{
			/* wake up all */
			pthread_cond_signal(&(entry->condvar));
			/* and the nice thing, they will wake us again when their work is done */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
		/* ok, we are alone now, no threads waiting in the entry's condvar */
		this->delete_entry(this, entry);
		this->logger->log(this->logger,CONTROL | MORE,"Delete of IKE_SA successful");
		retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR,"Fatal Error: Tried to delete nonexisting IKE_SA");
		retval = NOT_FOUND;
	}

	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

/**
 * Implements ike_sa_manager_t.destroy.
 */
static void destroy(private_ike_sa_manager_t *this)
{
	/* destroy all list entries */
	linked_list_t *list = this->ike_sa_list;
	iterator_t *iterator;
	ike_sa_entry_t *entry;
	
	pthread_mutex_lock(&(this->mutex));
	
	this->logger->log(this->logger,CONTROL | MORE,"Going to destroy IKE_SA manager and all managed IKE_SA's");
	
	/* Step 1: drive out all waiting threads  */
	list->create_iterator(list, &iterator, TRUE);

	this->logger->log(this->logger,CONTROL | MOST,"Set driveout flags for all stored IKE_SA's");
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;	
	}

	this->logger->log(this->logger,CONTROL | MOST,"Wait for all threads to leave IKE_SA's");
	/* Step 2: wait until all are gone */
	iterator->reset(iterator);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		while (entry->waiting_threads)
		{
			/* wake up all */
			pthread_cond_signal(&(entry->condvar));
			/* go sleeping until they are gone */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));		
		}
	}
	this->logger->log(this->logger,CONTROL | MOST,"Delete all IKE_SA's");
	/* Step 3: delete all entries */
	iterator->destroy(iterator);

	while (list->get_count(list) > 0)
	{
		list->get_first(list, (void**)&entry);
		this->delete_entry(this, entry);
	}
	list->destroy(list);
	this->logger->log(this->logger,CONTROL | MOST,"IKE_SA's deleted");
	pthread_mutex_unlock(&(this->mutex));

	/* destroy logger at end */
	global_logger_manager->destroy_logger(global_logger_manager,this->logger);

	allocator_free(this);
}

/*
 * Described in header
 */
ike_sa_manager_t *ike_sa_manager_create()
{
	private_ike_sa_manager_t *this = allocator_alloc_thing(private_ike_sa_manager_t);

	/* assign public functions */
	this->public.destroy = (void(*)(ike_sa_manager_t*))destroy;
	this->public.create_and_checkout = (void(*)(ike_sa_manager_t*, ike_sa_t **sa))create_and_checkout;
	this->public.checkout = (status_t(*)(ike_sa_manager_t*, ike_sa_id_t *sa_id, ike_sa_t **sa))checkout;
	this->public.checkin = (status_t(*)(ike_sa_manager_t*, ike_sa_t *sa))checkin;
	this->public.delete = (status_t(*)(ike_sa_manager_t*, ike_sa_id_t *sa_id))delete;
	this->public.checkin_and_delete = (status_t(*)(ike_sa_manager_t*, ike_sa_t *ike_sa))checkin_and_delete;

	/* initialize private functions */
	this->get_next_spi = get_next_spi;
	this->get_entry_by_sa = get_entry_by_sa;
	this->get_entry_by_id = get_entry_by_id;
	this->delete_entry = delete_entry;

	/* initialize private variables */
	this->logger = global_logger_manager->create_logger(global_logger_manager,IKE_SA_MANAGER,NULL);
	
	this->ike_sa_list = linked_list_create();

	pthread_mutex_init(&(this->mutex), NULL);

	this->next_spi = 0;

	return (ike_sa_manager_t*)this;
}
