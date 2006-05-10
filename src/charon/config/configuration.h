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
	 * The timeout values are managed by the configuration, so 
	 * another backoff algorithm may be implemented here.
	 * 
	 * @param this				calling object
	 * @param retransmit_count	number of times a message was retransmitted so far
	 * @param[out] timeout		the new retransmit timeout in milliseconds
	 * 
	 * @return		
	 * 							- FAILED, if the message should not be retransmitted
	 * 							- SUCCESS
	 */
	status_t (*get_retransmit_timeout) (configuration_t *this, u_int32_t retransmit_count, u_int32_t *timeout);
	
	/**
	 * @brief Returns the timeout for an half open IKE_SA in ms.
	 * 
	 * Half open means that the IKE_SA is still in one of the following states:
	 *  - INITIATOR_INIT
	 *  - RESPONDER_INIT
	 *  - IKE_SA_INIT_REQUESTED
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 * 
	 * @param this				calling object
	 * @return					timeout in milliseconds (ms)
	 */	
	u_int32_t (*get_half_open_ike_sa_timeout) (configuration_t *this);

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
