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

#include "allocator.h"
#include "ike_sa_manager.h"
#include "linked_list.h"
#include "ike_sa_id.h"

/**
 * @brief An entry in the linked list, contains IKE_SA, locking and lookup data.
 */
typedef struct ike_sa_entry_s ike_sa_entry_t;
struct ike_sa_entry_s {
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
	 * does this SA let new treads in?
	 */
	bool driveout_new_threads;
	/**
	 * does this SA drives out new threads?
	 */
	bool driveout_waiting_threads;;
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

	this->destroy = ike_sa_entry_destroy;
	this->waiting_threads = 0;
	pthread_cond_init(&(this->condvar), NULL);
	/* we set checkout flag when we really give it out */
	this->checked_out = FALSE;
	this->driveout_new_threads = FALSE;
	this->driveout_waiting_threads = FALSE;
	ike_sa_id->clone(ike_sa_id, &(this->ike_sa_id));
	this->ike_sa = ike_sa_create(ike_sa_id);
	return this;
}

/**
 * Additional private members to ike_sa_manager_t
 */
typedef struct private_ike_sa_manager_s private_ike_sa_manager_t;
struct private_ike_sa_manager_s {
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
	 * @param spi[out]		spi will be written here
	 * @return				SUCCESS or,
	 * 						OUT_OF_RES when we already served 2^64 SPIs ;-)
	 */
	 status_t (*get_next_spi) (private_ike_sa_manager_t *this, spi_t *spi);
	/**
	 * @brief find the ike_sa_entry in the list by SPIs
	 *
	 * This function simply iterates over the linked list. A hash-table
	 * would be more efficient when storing a lot of IKE_SAs...
	 *
	 * @param this			the ike_sa_manager containing the list
	 * @param ike_sa_id		id of the ike_sa, containing SPIs
	 * @param entry[out]	pointer to set to the found entry
	 * @return				SUCCESS when found,
	 * 						NOT_FOUND when no such ike_sa_id in list
	 */
	 status_t (*get_entry_by_id) (private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_entry_t **entry);
	 /**
	 * @brief find the ike_sa_entry in the list by pointer to SA.
	 *
	 * This function simply iterates over the linked list. A hash-table
	 * would be more efficient when storing a lot of IKE_SAs...
	 *
	 * @param this			the ike_sa_manager containing the list
	 * @param ike_sa		pointer to the ike_sa
	 * @param entry[out]	pointer to set to the found entry
	 * @return				SUCCESS when found,
	 * 						NOT_FOUND when no such ike_sa_id in list
	 */
	 status_t (*get_entry_by_sa) (private_ike_sa_manager_t *this, ike_sa_t *ike_sa, ike_sa_entry_t **entry);
	 /**
	  * @brief delete an entry from the linked list
	  *
	  * @param this			the ike_sa_manager containing the list
	  * @param entry		entry to delete
	  * @return				SUCCESS when found,
	  * 					NOT_FOUND when no such ike_sa_id in list
	  */
	 status_t (*delete_entry) (private_ike_sa_manager_t *this, ike_sa_entry_t *entry);
	 /**
	  * lock for exclusivly accessing the manager
	  */
	 pthread_mutex_t mutex;

	 /**
	  * Linked list with entries for the ike_sa
	  */
	 linked_list_t *list;
	 /**
	  * Next SPI, needed for incremental creation of SPIs
	  */
	 spi_t next_spi;
};


/**
 * @see private_ike_sa_manager_t.get_entry_by_id
 */
static status_t get_entry_by_id(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_entry_t **entry)
{
	linked_list_t *list = this->list;
	linked_list_iterator_t *iterator;
	list->create_iterator(list, &iterator, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		bool are_equal = FALSE;
		iterator->current(iterator, (void**)&current);
		current->ike_sa_id->equals(current->ike_sa_id, ike_sa_id, &are_equal);
		if (are_equal)
		{
			*entry = current;
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * @see private_ike_sa_manager_t.get_entry_by_sa
 */
static status_t get_entry_by_sa(private_ike_sa_manager_t *this, ike_sa_t *ike_sa, ike_sa_entry_t **entry)
{
	linked_list_t *list = this->list;
	linked_list_iterator_t *iterator;
	list->create_iterator(list, &iterator, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		iterator->current(iterator, (void**)&current);
		if (current->ike_sa == ike_sa)
		{
			*entry = current;
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * @see private_ike_sa_manager_t.delete_entry
 */
static status_t delete_entry(private_ike_sa_manager_t *this, ike_sa_entry_t *entry)
{
	linked_list_t *list = this->list;
	linked_list_iterator_t *iterator;
	list->create_iterator(list, &iterator, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		iterator->current(iterator, (void**)&current);
		if (current == entry) 
		{
			list->remove(list, iterator);
			entry->destroy(entry);
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;	
}


/**
 * @see private_ike_sa_manager_t.get_next_spi
 */
static status_t get_next_spi(private_ike_sa_manager_t *this, spi_t *spi)
{
	this->next_spi.low ++;
	if (this->next_spi.low == 0) {
		/* overflow of lower int in spi */
		this->next_spi.high ++;
		if (this->next_spi.high == 0) {
			/* our software ran so incredible stable, we have no more
			 * SPIs to give away :-/.  */
			 return OUT_OF_RES;
		}
	}
	*spi = this->next_spi;
	return SUCCESS;
}


/**
 * @see ike_sa_manager_s.checkout_ike_sa
 */
static status_t checkout(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_t **ike_sa)
{
	bool responder_spi_set;
	bool initiator_spi_set;
	status_t retval;

	pthread_mutex_lock(&(this->mutex));

	responder_spi_set = ike_sa_id->responder_spi_is_set(ike_sa_id);
	initiator_spi_set = ike_sa_id->initiator_spi_is_set(ike_sa_id);

	if (initiator_spi_set && responder_spi_set)
	{
		/* we SHOULD have an IKE_SA for these SPIs in the list,
		 * if not, we cant handle the request...
		 */
		 ike_sa_entry_t *entry;
		 /* look for the entry */
		 if (this->get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
		 {
		 	/* can we give this out to new requesters? */
		 	if (entry->driveout_new_threads)
		 	{
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
			 		retval = NOT_FOUND;
			 	}
			 	else
			 	{
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
		spi_t responder_spi;
		ike_sa_entry_t *new_ike_sa_entry;

		/* set SPIs, we are the responder */
		this->get_next_spi(this, &responder_spi);
		/* we also set arguments spi, so its still valid */
		ike_sa_id->set_responder_spi(ike_sa_id, responder_spi);

		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(ike_sa_id);
		this->list->insert_last(this->list, new_ike_sa_entry);

		/* check ike_sa out */
		new_ike_sa_entry->checked_out = TRUE;
		*ike_sa = new_ike_sa_entry->ike_sa;

		 /* DON'T use return, we must unlock the mutex! */
		retval = SUCCESS;
	}
	else if (!initiator_spi_set && !responder_spi_set)
	{
		/* creation of an IKE_SA from local site,
		 * we are the initiator!
		 */
		spi_t initiator_spi;
		ike_sa_entry_t *new_ike_sa_entry;
		
		this->get_next_spi(this, &initiator_spi);

		/* we also set arguments SPI, so its still valid */
		ike_sa_id->set_initiator_spi(ike_sa_id, initiator_spi);

		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(ike_sa_id);
		this->list->insert_last(this->list, new_ike_sa_entry);

		/* check ike_sa out */
		new_ike_sa_entry->checked_out = TRUE;
		*ike_sa = new_ike_sa_entry->ike_sa;

		/* DON'T use return, we must unlock the mutex! */
		retval = SUCCESS;
	}
	else
	{
		/* responder set, initiator not: here is something seriously wrong! */

		/* DON'T use return, we must unlock the mutex! */
		retval = INVALID_ARG;
	}

	pthread_mutex_unlock(&(this->mutex));
	/* OK, unlocked... */
	return retval;
}

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
		pthread_cond_signal(&(entry->condvar));
	 	retval = SUCCESS;
	}
	else
	{
		/* this SA is no more, this REALLY should not happen */
		retval = NOT_FOUND;
	}
	pthread_mutex_unlock(&(this->mutex));
	return retval;
}



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
		while (entry->waiting_threads)
		{
			/* let the other threads do some work*/
			pthread_cond_signal(&(entry->condvar));
			/* and the nice thing, they will wake us again when their work is done */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
		/* ok, we are alone now, no threads waiting in the entry's condvar */
		this->delete_entry(this, entry);
		retval = SUCCESS;
	}
	else
	{
		retval = NOT_FOUND;
	}

	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

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
		retval = SUCCESS;
	}
	else
	{
		retval = NOT_FOUND;
	}

	pthread_mutex_unlock(&(this->mutex));
	return retval;
}

static status_t destroy(private_ike_sa_manager_t *this)
{
	/* destroy all list entries */
	linked_list_t *list = this->list;
	linked_list_iterator_t *iterator;
	
	pthread_mutex_lock(&(this->mutex));
	
	/* Step 1: drive out all waiting threads  */
	list->create_iterator(list, &iterator, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		iterator->current(iterator, (void**)&entry);
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;	
	}
	/* Step 2: wait until all are gone */
	iterator->reset(iterator);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		iterator->current(iterator, (void**)&entry);
		while (entry->waiting_threads)
		{
			/* wake up all */
			pthread_cond_signal(&(entry->condvar));
			/* go sleeping until they are gone */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));		
		}
	}
	/* Step 3: delete all entries */
	iterator->reset(iterator);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		iterator->current(iterator, (void**)&entry);
		this->delete_entry(this, entry);
	}
	iterator->destroy(iterator);

	list->destroy(list);
	
	pthread_mutex_unlock(&(this->mutex));

	allocator_free(this);

	return SUCCESS;
}


ike_sa_manager_t *ike_sa_manager_create()
{
	private_ike_sa_manager_t *this = allocator_alloc_thing(private_ike_sa_manager_t);

	/* assign public functions */
	this->public.destroy = (status_t(*)(ike_sa_manager_t*))destroy;
	this->public.checkout = (status_t(*)(ike_sa_manager_t*, ike_sa_id_t *sa_id, ike_sa_t **sa))checkout;
	this->public.checkin = (status_t(*)(ike_sa_manager_t*, ike_sa_t *sa))checkin;
	this->public.delete = (status_t(*)(ike_sa_manager_t*, ike_sa_id_t *sa_id))delete;
	this->public.checkin_and_delete = (status_t(*)(ike_sa_manager_t*, ike_sa_t *ike_sa))checkin_and_delete;

	/* initialize private data */
	this->get_next_spi = get_next_spi;
	this->get_entry_by_sa = get_entry_by_sa;
	this->get_entry_by_id = get_entry_by_id;
	this->delete_entry = delete_entry;

	this->list = linked_list_create();
	if (this->list == NULL)
	{
		allocator_free(this);
		return NULL;
	}

	pthread_mutex_init(&(this->mutex), NULL);

	this->next_spi.low = 1;
	this->next_spi.high = 0;

	return (ike_sa_manager_t*)this;
}
