/*
 * Copyright (C) 2005-2007 Martin Willi
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

/**
 * @defgroup receiver receiver
 * @{ @ingroup network
 */

#ifndef RECEIVER_H_
#define RECEIVER_H_

typedef struct receiver_t receiver_t;

#include <library.h>
#include <utils/host.h>

/**
 * Receives packets from the socket and adds them to the job queue.
 *
 * The receiver starts a thread, which reads on the blocking socket. A received
 * packet is preparsed and a process_message_job is queued in the job queue.
 *
 * To endure DoS attacks, cookies are enabled when to many IKE_SAs are half
 * open. The calculation of cookies is slightly different from the proposed
 * method in RFC4306. We do not include a nonce, because we think the advantage
 * we gain does not justify the overhead to parse the whole message.
 * Instead of VersionIdOfSecret, we include a timestamp. This allows us to
 * find out which key was used for cookie creation. Further, we can set a
 * lifetime for the cookie, which allows us to reuse the secret for a longer
 * time.
 *		 COOKIE = time | sha1( IPi | SPIi | time | secret )
 *
 * The secret is changed after a certain amount of cookies sent. The old
 * secret is stored to allow a clean migration between secret changes.
 *
 * Further, the number of half-initiated IKE_SAs is limited per peer. This
 * mades it impossible for a peer to flood the server with its real IP address.
 */
struct receiver_t {

	/**
	 * Destroys a receiver_t object.
	 */
	void (*destroy) (receiver_t *receiver);
};

/**
 * Create a receiver_t object.
 *
 * The receiver thread will start working, get data
 * from the socket and add those packets to the job queue.
 *
 * @return	receiver_t object, NULL if initialization fails
 */
receiver_t * receiver_create(void);

#endif /** RECEIVER_H_ @}*/
