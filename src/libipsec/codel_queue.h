/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

/**
 * @defgroup codel_queue codel_queue
 * @{ @ingroup ipsec
 */

#ifndef CODEL_QUEUE_H_
#define CODEL_QUEUE_H_

typedef struct codel_queue_t codel_queue_t;

#include <library.h>

/**
 * A CoDel implementation.
 *
 * Implements a packet queue with "Controlled Delay", as described on
 *    http://queue.acm.org/detail.cfm?id=2209336
 */
struct codel_queue_t {

	/**
	 * Enqueue a packet to the CoDel queue.
	 *
	 * @param packet		packet to enqueue
	 * @param len			len of packet to enqueue
	 */
	void (*enqueue)(codel_queue_t *this, void *packet, u_int len);

	/**
	 * Dequeue a queued packet from the CoDel queue.
	 *
	 * This call is blocking and does not return before a packet could be
	 * dequeued.
	 *
	 * @return				dequeued packet
	 */
	void* (*dequeue)(codel_queue_t *this);

	/**
	 * Destroy a codel_queue_t, with all queued packets.
	 */
	void (*destroy)(codel_queue_t *this);
};

/**
 * Create a codel_queue instance.
 *
 * @param destroy_offset		offset of destructor in queued packet objects
 * @param mtu				maximum transfer unit of queue link
 */
codel_queue_t *codel_queue_create(int destroy_offset, u_int mtu);

#endif /** CODEL_QUEUE_H_ @}*/
