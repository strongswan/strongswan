/**
 * @file send_queue.h
 * 
 * @brief Send-Queue based on linked_list_t
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

#ifndef SEND_QUEUE_H_
#define SEND_QUEUE_H_

#include "types.h"
#include "packet.h"

/**
 * @brief Send-Queue
 *
 * Although the send-queue is based on a linked_list_t 
 * all access functions are thread-save implemented
 */
typedef struct send_queue_s send_queue_t;

struct send_queue_s {
	
	/**
	 * @brief returns number of packets in queue
	 * 
	 * @param send_queue_t calling object
 	 * @param[out] count integer pointer to store the count in
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_count) (send_queue_t *send_queue, int *count);

	/**
	 * @brief get the next packet from the queue
	 * 
	 * If the queue is empty, this function blocks until a packet can be returned.
	 * 
	 * After using, the returned packet has to get destroyed by the caller.
	 * 
	 * @param send_queue_t calling object
 	 * @param[out] packet pointer to a packet_t pointer where to packet is returned to
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get) (send_queue_t *send_queue, packet_t **packet);
	
	/**
	 * @brief adds a packet to the queue
	 * 
	 * This function is non blocking and adds a packet_t to the list.
	 * The specific packet-object has to get destroyed by the thread which 
	 * removes the packet.
	 * 
	 * @param send_queue_t calling object
 	 * @param[in] packet packet_t to add to the queue (packet is not copied)
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*add) (send_queue_t *send_queue, packet_t *packet);

	/**
	 * @brief destroys a send_queue object
	 * 
	 * @warning The caller of this function has to make sure
	 * that no thread is going to add or get a packet from the send_queue
	 * after calling this function.
	 * 
	 * @param send_queue_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (send_queue_t *send_queue);
};

/**
 * @brief Creates an empty send_queue_t
 * 
 * @return send_queue_t empty send_queue_t
 */
send_queue_t *send_queue_create();

#endif /*SEND_QUEUE_H_*/
