/**
 * @file configuration.h
 * 
 * @brief Interface configuration_t.
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

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include <types.h>


typedef struct configuration_t configuration_t;

/**
 * @brief The interface for various daemon related configs.
 * 
 * @b Constructors:
 * 	- configuration_create()
 * 
 * @ingroup config
 */
struct configuration_t {

	/**
	 * @brief Returns the retransmit timeout.
	 *
	 * A return value of zero means the request should not be retransmitted again.
	 * The retransmission algorithm uses sequences of retransmits, in which
	 * every sequence contains exponential delayed retransmits. These
	 * sequences are compareable to the keyingtries mechanism used in pluto.
	 *
	 * @param this				calling object
	 * @param retransmitted		number of times a message was retransmitted so far
	 * @param max_sequences		maximum number of retransmission sequences to allow
	 * @return					time in milliseconds, when to schedule next retransmit
	 */
	u_int32_t (*get_retransmit_timeout) (configuration_t *this, 
										 u_int32_t retransmitted, 
										 u_int32_t max_sequences);
	
	/**
	 * @brief Returns the timeout for an half open IKE_SA in ms.
	 *
	 * Half open means that the IKE_SA is still on a not established state
	 *
	 * @param this				calling object
	 * @return					timeout in milliseconds (ms)
	 */
	u_int32_t (*get_half_open_ike_sa_timeout) (configuration_t *this);

	/**
	 * @brief Returns the keepalive interval in ms.
	 * 
	 * The keepalive interval defines the idle time after which a
	 * NAT keepalive packet should be sent.
	 * 
	 * @param this				calling object
	 * @return					interval in seconds
	 */	
	u_int32_t (*get_keepalive_interval) (configuration_t *this);

	/**
	 * @brief Destroys a configuration_t object.
	 * 
	 * @param this 					calling object
	 */
	void (*destroy) (configuration_t *this);
};

/**
 * @brief Creates a configuration backend.
 * 
 * @return static_configuration_t object
 * 
 * @ingroup config
 */
configuration_t *configuration_create(void);

#endif /*CONFIGURATION_H_*/
