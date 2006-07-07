/**
 * @file send_queue.h
 *
 * @brief Interface of send_queue_t.
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

#ifndef SEND_QUEUE_H_
#define SEND_QUEUE_H_

#include <types.h>
#include <network/packet.h>


typedef struct send_queue_t send_queue_t;

/**
 * @brief The send queue stores packet for the sender_t instance.
 * 
 * The sender_t will send them consequently over the wire.
 * Although the send-queue is based on a linked_list_t
 * all access functions are thread-save implemented.
 * 
 * @b Constructors:
 * - send_queue_create()
 * 
 * @ingroup queues
 */
struct send_queue_t {

	/**
	 * @brief returns number of packets in queue
	 *
	 * @param send_queue_t 	calling object
 	 * @param[out] 			count integer pointer to store the count in
	 * @returns 			number of items in queue
	 */
	int (*get_count) (send_queue_t *send_queue);

	/**
	 * @brief get the next packet from the queue.
	 *
	 * If the queue is empty, this function blocks until a packet can be returned.
	 *
	 * After using, the returned packet has to get destroyed by the caller.
	 *
	 * @param send_queue_t 	calling object
	 * @return 				next packet from the queue
	 */
	packet_t *(*get) (send_queue_t *send_queue);

	/**
	 * @brief adds a packet to the queue.
	 *
	 * This function is non blocking and adds a packet_t to the list.
	 * The specific packet object has to get destroyed by the thread which
	 * removes the packet.
	 *
	 * @param send_queue_t 	calling object
 	 * @param packet 		packet_t to add to the queue (packet is not copied)
	 */
	void (*add) (send_queue_t *send_queue, packet_t *packet);

	/**
	 * @brief destroys a send_queue object.
	 *
	 * @warning The caller of this function has to make sure
	 * that no thread is going to add or get a packet from the send_queue
	 * after calling this function.
	 *
	 * @param send_queue_t 	calling object
	 */
	void (*destroy) (send_queue_t *send_queue);
};

/**
 * @brief Creates an empty send_queue_t.
 *
 * @return send_queue_t object
 * 
 * @ingroup queues
 */
send_queue_t *send_queue_create(void);

#endif /*SEND_QUEUE_H_*/
