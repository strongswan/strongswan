/**
 * @file configuration.c
 * 
 * @brief Implementation of configuration_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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
#include <math.h>

#include "configuration.h"

#include <types.h>

/**
 * Timeout in milliseconds after that a half open IKE_SA gets deleted.
 */
#define HALF_OPEN_IKE_SA_TIMEOUT 30000

/**
 * The retransmission algorithm uses a multiple sequences.
 * Each sequence contains multiple retransmits. Those retransmits
 * are sent using a exponential backoff algorithm. The sequences
 * are retried with linear timings:
 *
 * <------sequence---------><------sequence---------><------sequence--------->
 *
 * T-R---R-----R---------R--R-R---R-----R---------R--R-R---R-----R---------R--X
 *
 * T = first transmit
 * R = retransmit
 * X = giving up, peer is dead
 *
 * if (retransmit >= TRIES * sequences)
 *     => abort
 * TIMEOUT * (BASE ** (try % TRIES))
 *
 * Using an initial TIMEOUT of 4s, a BASE of 1.8, 5 TRIES
 * per sequnce and 3 sequences, this gives us:
 *
 *                        | relative | absolute
 * ---------------------------------------------------------
 * 4s * (1.8 ** (0  % 5)) =    4s         4s
 * 4s * (1.8 ** (1  % 5)) =    7s        11s
 * 4s * (1.8 ** (2  % 5)) =   13s        24s
 * 4s * (1.8 ** (3  % 5)) =   23s        47s
 * 4s * (1.8 ** (4  % 5)) =   42s        89s
 * 4s * (1.8 ** (5  % 5)) =   76s       165s
 * 4s * (1.8 ** (6  % 5)) =    4s       169s
 * 4s * (1.8 ** (7  % 5)) =    7s       176s
 * 4s * (1.8 ** (8  % 5)) =   13s       189s
 * 4s * (1.8 ** (9  % 5)) =   23s       212s
 * 4s * (1.8 ** (10 % 5)) =   42s       254s
 * 4s * (1.8 ** (11 % 5)) =   76s       330s
 * 4s * (1.8 ** (12 % 5)) =    4s       334
 * 4s * (1.8 ** (13 % 5)) =    7s       341s
 * 4s * (1.8 ** (14 % 5)) =   13s       354s
 * 4s * (1.8 ** (15 % 5)) =   23s       377s
 * 4s * (1.8 ** (16 % 5)) =   42s       419s
 * 4s * (1.8 ** (17 % 5)) =   76s       495s
 *
 * If the configuration uses 1 sequence, the peer is considered dead
 * after 2min 45s when no reply comes in. If it uses 3 sequences, after
 * 8min 15s the DPD action is executed...
 */

/**
 * First retransmit timeout in milliseconds.
 * Timeout value is increasing in each retransmit round.
 */
#define RETRANSMIT_TIMEOUT 4000

/**
 * Base which is raised to the power of the retransmission count.
 */
#define RETRANSMIT_BASE 1.8

/**
 * Number of retransmits done in a retransmit sequence
 */
#define RETRANSMIT_TRIES 5

/**
 * Keepalive interval in seconds.
 */
#define KEEPALIVE_INTERVAL 20


typedef struct private_configuration_t private_configuration_t;

/**
 * Private data of an configuration_t object.
 */
struct private_configuration_t {

	/**
	 * Public part of configuration_t object.
	 */
	configuration_t public;

};

/**
 * Implementation of configuration_t.get_retransmit_timeout.
 */
static u_int32_t get_retransmit_timeout (private_configuration_t *this,
										 u_int32_t retransmit_count,
										 u_int32_t max_sequences)
{
	if (max_sequences != 0 && 
		retransmit_count >= RETRANSMIT_TRIES * max_sequences)
	{
		/* give up */
		return 0;
	}
	return (u_int32_t)(RETRANSMIT_TIMEOUT *
					   pow(RETRANSMIT_BASE, retransmit_count % RETRANSMIT_TRIES));
}

/**
 * Implementation of configuration_t.get_half_open_ike_sa_timeout.
 */
static u_int32_t get_half_open_ike_sa_timeout (private_configuration_t *this)
{
	return HALF_OPEN_IKE_SA_TIMEOUT;
}

/**
 * Implementation of configuration_t.get_keepalive_interval.
 */
static u_int32_t get_keepalive_interval (private_configuration_t *this)
{
	return KEEPALIVE_INTERVAL;
}

/**
 * Implementation of configuration_t.destroy.
 */
static void destroy(private_configuration_t *this)
{
	free(this);
}

/*
 * Described in header-file
 */
configuration_t *configuration_create()
{
	private_configuration_t *this = malloc_thing(private_configuration_t);
	
	/* public functions */
	this->public.destroy = (void(*)(configuration_t*))destroy;
	this->public.get_retransmit_timeout = (u_int32_t (*) (configuration_t*,u_int32_t,u_int32_t))get_retransmit_timeout;
	this->public.get_half_open_ike_sa_timeout = (u_int32_t (*) (configuration_t*)) get_half_open_ike_sa_timeout;
	this->public.get_keepalive_interval = (u_int32_t (*) (configuration_t*)) get_keepalive_interval;
	
	return (&this->public);
}
