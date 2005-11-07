/**
 * @file sender.c
 * 
 * @brief Implements the Sender Thread encapsulated in the sender_t-object
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
 
#include <stdlib.h>
#include <pthread.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
 
#include "sender.h"
#include "socket.h"
#include "packet.h"
#include "send_queue.h"
#include "globals.h"
 
/**
 * Private data of a sender object
 */
typedef struct private_sender_s private_sender_t;
 
struct private_sender_s { 	
	/**
	 * Public part of a sender object
	 */
	 sender_t public;
	 
	 /**
	  * Assigned thread to the sender_t-object
	  */
	 pthread_t assigned_thread;

};

/**
 * Thread function started at creation of the sender object
 * 
 * @param this assigned sender object
 * @return SUCCESS if thread_function ended successfully, FAILED otherwise
 */
static void sender_thread_function(private_sender_t * this)
{
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	packet_t * current_packet;
	
	while (1)
	{
		while (global_send_queue->get(global_send_queue,&current_packet) == SUCCESS)
		{
			if (	global_socket->send(global_socket,current_packet) == SUCCESS)
			{
				current_packet->destroy(current_packet);				
			}
			else
			{
				/* Packet could not be sent */
				/* TODO LOG it */	
			}

		}

		/* NOT GOOD !!!!!! */
		/* TODO LOG it */	
	}
	
	
}

/**
 * Implementation of sender_t's destroy function
 */
static status_t destroy(private_sender_t *this)
{
	pthread_cancel(this->assigned_thread);
	
	pthread_join(this->assigned_thread, NULL);

	pfree(this);
	return SUCCESS;
}


sender_t * sender_create()
{
	private_sender_t *this = alloc_thing(private_sender_t,"private_sender_t");
	
	this->public.destroy = (status_t(*)(sender_t*)) destroy;
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))sender_thread_function, this) != 0)
	{
		/* thread could not be created  */
		pfree(this);
		return NULL;
	}
	
	return &(this->public);
}
