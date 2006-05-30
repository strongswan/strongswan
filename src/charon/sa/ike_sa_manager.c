/**
 * @file ike_sa_manager.c
 *
 * @brief Implementation of ike_sa_mananger_t.
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
	 * @brief Get next spi.
	 *
	 * We give out SPIs from a pseudo random source
	 * 
	 * @param this			the ike_sa_manager
	 * @return 				the next spi
	 */
	u_int64_t (*get_next_spi) (private_ike_sa_manager_t *this);

	/**
	 * @brief Find the ike_sa_entry_t object in the list by SPIs.
	 *
	 * This function simply iterates over the linked list. A hash-table
	 * would be more efficient when storing a lot of IKE_SAs...
	 *
	 * @param this			calling object
	 * @param ike_sa_id		id of the ike_sa, containing SPIs
	 * @param[out] entry	pointer to set to the found entry
	 * @return				
	 * 						- SUCCESS when found,
	 * 						- NOT_FOUND when no such ike_sa_id in list
	 */
	 status_t (*get_entry_by_id) (private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_entry_t **entry);

	 /**
	 * @brief Find the ike_sa_entry_t in the list by pointer to SA.
	 *
	 * This function simply iterates over the linked list. A hash-table
	 * would be more efficient when storing a lot of IKE_SAs...
	 *
	 * @param this			calling object
	 * @param ike_sa		pointer to the ike_sa
	 * @param[out] entry	pointer to set to the found entry
	 * @return				
	 * 						- SUCCESS when found,
	 * 						- NOT_FOUND when no such ike_sa_id in list
	 */
	 status_t (*get_entry_by_sa) (private_ike_sa_manager_t *this, ike_sa_t *ike_sa, ike_sa_entry_t **entry);
	 
	 /**
	  * @brief Felete an entry from the linked list.
	  *
	  * @param this			calling object
	  * @param entry		entry to delete
	  * @return				
	  * 					- SUCCESS when found,
	  * 					- NOT_FOUND when no such ike_sa_id in list
	  */
	 status_t (*delete_entry) (private_ike_sa_manager_t *this, ike_sa_entry_t *entry);

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
			if ((current->ike_sa_id->get_initiator_spi(current->ike_sa_id) == ike_sa_id->get_initiator_spi(ike_sa_id))
				&& (ike_sa_id->is_initiator(ike_sa_id) == current->ike_sa_id->is_initiator(current->ike_sa_id)))
			{
		 		this->logger->log(this->logger, CONTROL|LEVEL2, "Found entry by initiator spi %d",
								  ike_sa_id->get_initiator_spi(ike_sa_id));
				*entry = current;
				status = SUCCESS;
				break;
			}
		}
		else if (ike_sa_id->get_responder_spi(ike_sa_id) == 0)
		{
			if ((current->ike_sa_id->get_initiator_spi(current->ike_sa_id) == ike_sa_id->get_initiator_spi(ike_sa_id))
				&& (ike_sa_id->is_initiator(ike_sa_id) == current->ike_sa_id->is_initiator(current->ike_sa_id)))
			{
		 		this->logger->log(this->logger, CONTROL|LEVEL2, "Found entry by initiator spi %d",
								  ike_sa_id->get_initiator_spi(ike_sa_id));
				*entry = current;
				status = SUCCESS;
				break;
			}			
		}
		if (current->ike_sa_id->equals(current->ike_sa_id, ike_sa_id))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "Found entry by full ID");
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
	 		this->logger->log(this->logger, CONTROL|LEVEL2, "Found entry by pointer");
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
	 		this->logger->log(this->logger, CONTROL|LEVEL2, "Found entry by pointer. Going to delete it.");
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
 * Implementation of private_ike_sa_manager_t.get_next_spi.
 */
static u_int64_t get_next_spi(private_ike_sa_manager_t *this)
{
	u_int64_t spi;
	
	this->randomizer->get_pseudo_random_bytes(this->randomizer, 8, (u_int8_t*)&spi);
	
	return spi;
}

/**
 * Implementation of of ike_sa_manager.create_and_checkout.
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
	this->logger->log(this->logger, CONTROL|LEVEL1, "New IKE_SA created and added to list of known IKE_SA's");
	new_ike_sa_entry->checked_out = TRUE;
	*ike_sa = new_ike_sa_entry->ike_sa;

	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implementation of of ike_sa_manager.checkout.
 */
static status_t checkout(private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id, ike_sa_t **ike_sa)
{
	bool responder_spi_set;
	bool initiator_spi_set;
	bool original_initiator;
	status_t retval;
	
	/* each access is locked */
	pthread_mutex_lock(&(this->mutex));
	
	responder_spi_set = (FALSE != ike_sa_id->get_responder_spi(ike_sa_id));
	initiator_spi_set = (FALSE != ike_sa_id->get_initiator_spi(ike_sa_id));
	original_initiator = ike_sa_id->is_initiator(ike_sa_id);
	
	if ((initiator_spi_set && responder_spi_set) ||
		((initiator_spi_set && !responder_spi_set) && (original_initiator)))
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
		 		this->logger->log(this->logger, CONTROL|LEVEL1, "Drive out new thread for existing IKE_SA");
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
					this->logger->log(this->logger, CONTROL|LEVEL1, "Drive out waiting thread for existing IKE_SA");
					retval = NOT_FOUND;
				}
				else
				{
					this->logger->log(this->logger, CONTROL|LEVEL2, "IKE SA successfully checked out");
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
			this->logger->log(this->logger, ERROR|LEVEL1, "IKE SA not stored in known IKE_SA list");
			/* looks like there is no such IKE_SA, better luck next time... */
			/* DON'T use return, we must unlock the mutex! */
			retval = NOT_FOUND;
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
		responder_spi = this->get_next_spi(this);
		
		/* we also set arguments spi, so its still valid */
		ike_sa_id->set_responder_spi(ike_sa_id, responder_spi);
		
		/* create entry */
		new_ike_sa_entry = ike_sa_entry_create(ike_sa_id);
		
		this->ike_sa_list->insert_last(this->ike_sa_list, new_ike_sa_entry);
		
		/* check ike_sa out */
		this->logger->log(this->logger, CONTROL|LEVEL1 ,"IKE_SA added to list of known IKE_SA's");
		new_ike_sa_entry->checked_out = TRUE;
		*ike_sa = new_ike_sa_entry->ike_sa;
		
		retval = CREATED;
	}
	else
	{
		/* responder set, initiator not: here is something seriously wrong! */
 		this->logger->log(this->logger, ERROR|LEVEL1, "Invalid IKE_SA SPI's");
		/* DON'T use return, we must unlock the mutex! */
		retval = INVALID_ARG;
	}

	pthread_mutex_unlock(&(this->mutex));
	/* OK, unlocked... */
	return retval;
}

/**
 * Implementation of of ike_sa_manager.checkout_by_hosts.
 */
static status_t checkout_by_hosts(private_ike_sa_manager_t *this, host_t *me, host_t *other, ike_sa_t **ike_sa)
{
	iterator_t *iterator;
	ike_sa_id_t *ike_sa_id = NULL;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *current;
		host_t *sa_me, *sa_other;
		
		iterator->current(iterator, (void**)&current);
		sa_me = current->ike_sa->get_my_host(current->ike_sa);
		sa_other = current->ike_sa->get_other_host(current->ike_sa);
		
		/* one end may be default/any, but not both */
		if (me->is_anyaddr(me))
		{
			if (other->is_anyaddr(other))
			{
				break;
			}
			if (other->equals(other, sa_other))
			{
				/* other matches */
				ike_sa_id = current->ike_sa_id;
			}
		}
		else if (other->is_anyaddr(other))
		{
			if (me->equals(me, sa_me))
			{
				/* ME matches */
				ike_sa_id = current->ike_sa_id;
			}
		}
		else
		{
			if (me->equals(me, sa_me) && other->equals(other, sa_other))
			{
				/* both matches */
				ike_sa_id = current->ike_sa_id;
			}
		}
	}
	iterator->destroy(iterator);
	pthread_mutex_unlock(&(this->mutex));
	
	if (ike_sa_id)
	{
		/* checkout is done in the checkout function, since its rather complex */
		return checkout(this, ike_sa_id, ike_sa);
	}
	return NOT_FOUND;
}

/**
 * Implementation of ike_sa_manager_t.get_ike_sa_list.
 */
linked_list_t *get_ike_sa_list(private_ike_sa_manager_t* this)
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
 * Implementation of ike_sa_manager_t.get_ike_sa_list_by_name.
 */
linked_list_t *get_ike_sa_list_by_name(private_ike_sa_manager_t* this, const char *name)
{
	linked_list_t *list;
	iterator_t *iterator;
	
	pthread_mutex_lock(&(this->mutex));
	
	list = linked_list_create();
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		connection_t *connection;
		
		iterator->current(iterator, (void**)&entry);
		connection = entry->ike_sa->get_connection(entry->ike_sa);
		if (strcmp(name, connection->get_name(connection)) == 0)
		{
			list->insert_last(list, (void*)entry->ike_sa_id->clone(entry->ike_sa_id));
		}
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
	
	logger->log(logger, CONTROL, "Instances:");
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->ike_sa_list->create_iterator(this->ike_sa_list, TRUE);
	while (iterator->has_next(iterator))
	{
		ike_sa_entry_t *entry;
		iterator->current(iterator, (void**)&entry);
		entry->ike_sa->log_status(entry->ike_sa, logger, name);
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
	
	pthread_mutex_lock(&(this->mutex));

	/* look for the entry */
	if (this->get_entry_by_sa(this, ike_sa, &entry) == SUCCESS)
	{
		/* ike_sa_id must be updated */
		entry->ike_sa_id->replace_values(entry->ike_sa_id, ike_sa->get_id(ike_sa));
		/* signal waiting threads */
		entry->checked_out = FALSE;
		this->logger->log(this->logger, CONTROL|LEVEL1, "Checkin of IKE_SA successful.");
		pthread_cond_signal(&(entry->condvar));
	 	retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger, ERROR, "Tried to checkin nonexisting IKE_SA");
		/* this SA is no more, this REALLY should not happen */
		retval = NOT_FOUND;
	}
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
			/* let the other threads leave the manager */
			pthread_cond_broadcast(&(entry->condvar));
			/* and the nice thing, they will wake us again when their work is done */
			pthread_cond_wait(&(entry->condvar), &(this->mutex));
		}
		/* ok, we are alone now, no threads waiting in the entry's condvar */
		this->delete_entry(this, entry);
		this->logger->log(this->logger, CONTROL|LEVEL1, "Checkin and destroy of IKE_SA successful");
		retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR, "Tried to checkin and delete nonexisting IKE_SA");
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

	pthread_mutex_lock(&(this->mutex));

	if (this->get_entry_by_id(this, ike_sa_id, &entry) == SUCCESS)
	{
		/* we try a delete. If it succeeds, our job is done here. The
		 * other peer will reply, and the IKE SA gets the finally deleted...
		 */
		if (entry->ike_sa->delete(entry->ike_sa) == SUCCESS)
		{
			this->logger->log(this->logger, CONTROL|LEVEL1, "Initiated delete for IKE_SA");
		}
		/* but if the IKE SA is not in a state where the deletion is negotiated with
		 * the other peer, we can destroy the IKE SA on our own. For this, we must
		 * be sure that really NO other threads are waiting for this SA...
		 */
		else
		{
			/* mark it, so now new threads can acquire this SA */
			entry->driveout_new_threads = TRUE;
			/* wait until all workers have done their work */
			while (entry->waiting_threads)
			{
				/* wake up all */
				pthread_cond_broadcast(&(entry->condvar));
				/* and the nice thing, they will wake us again when their work is done */
				pthread_cond_wait(&(entry->condvar), &(this->mutex));
			}
			/* ok, we are alone now, no threads waiting in the entry's condvar */
			this->delete_entry(this, entry);
			this->logger->log(this->logger, CONTROL|LEVEL1, "Destroyed IKE_SA");
		}
		retval = SUCCESS;
	}
	else
	{
		this->logger->log(this->logger,ERROR, "Tried to delete nonexisting IKE_SA");
		retval = NOT_FOUND;
	}

	pthread_mutex_unlock(&(this->mutex));
	return retval;
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
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Going to destroy IKE_SA manager and all managed IKE_SA's");
	
	/* Step 1: drive out all waiting threads  */
	iterator = list->create_iterator(list, TRUE);

	this->logger->log(this->logger, CONTROL|LEVEL2, "Set driveout flags for all stored IKE_SA's");
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;	
	}

	this->logger->log(this->logger, CONTROL|LEVEL2, "Wait for all threads to leave IKE_SA's");
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
	this->logger->log(this->logger, CONTROL|LEVEL2, "Delete all IKE_SA's");
	/* Step 3: initiate deletion of all IKE_SAs */
	iterator->reset(iterator);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&entry);
		entry->ike_sa->delete(entry->ike_sa);
	}
	iterator->destroy(iterator);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Destroy all entries");
	/* Step 4: destroy all entries */
	while (list->get_count(list) > 0)
	{
		list->get_first(list, (void**)&entry);
		this->delete_entry(this, entry);
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
	this->public.create_and_checkout = (void(*)(ike_sa_manager_t*,ike_sa_t**))create_and_checkout;
	this->public.checkout = (status_t(*)(ike_sa_manager_t*, ike_sa_id_t*,ike_sa_t**))checkout;
	this->public.checkout_by_hosts = (status_t(*)(ike_sa_manager_t*,host_t*,host_t*,ike_sa_t**))checkout_by_hosts;
	this->public.get_ike_sa_list = (linked_list_t*(*)(ike_sa_manager_t*))get_ike_sa_list;
	this->public.get_ike_sa_list_by_name = (linked_list_t*(*)(ike_sa_manager_t*,const char*))get_ike_sa_list_by_name;
	this->public.log_status = (void(*)(ike_sa_manager_t*,logger_t*,char*))log_status;
	this->public.checkin = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin;
	this->public.delete = (status_t(*)(ike_sa_manager_t*,ike_sa_id_t*))delete_;
	this->public.checkin_and_destroy = (status_t(*)(ike_sa_manager_t*,ike_sa_t*))checkin_and_destroy;

	/* initialize private functions */
	this->get_next_spi = get_next_spi;
	this->get_entry_by_sa = get_entry_by_sa;
	this->get_entry_by_id = get_entry_by_id;
	this->delete_entry = delete_entry;

	/* initialize private variables */
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA_MANAGER);
	
	this->ike_sa_list = linked_list_create();

	pthread_mutex_init(&(this->mutex), NULL);

	this->randomizer = randomizer_create();

	return (ike_sa_manager_t*)this;
}
