/**
 * @file endpoint_notify.h
 * 
 * @brief Interface of endpoint_notify_t.
 * 
 */

/*
 * Copyright (C) 2007 Tobias Brunner
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


#ifndef ENDPOINT_NOTIFY_H_
#define ENDPOINT_NOTIFY_H_

#define P2P_PRIO_HOST   255
#define P2P_PRIO_SERVER 100
#define P2P_PRIO_PEER   120
#define P2P_PRIO_RELAY  0

typedef enum p2p_endpoint_family_t p2p_endpoint_family_t;
typedef enum p2p_endpoint_type_t p2p_endpoint_type_t;
typedef struct endpoint_notify_t endpoint_notify_t;

#include <encoding/payloads/notify_payload.h>

/**
 * @brief P2P endpoint families.
 *
 * @ingroup payloads
 */
enum p2p_endpoint_family_t {
	
	NO_FAMILY = 0,
	
	IPv4 = 1,
	
	IPv6 = 2,
	
	MAX_FAMILY = 3
	
};

/**
 * @brief P2P endpoint types.
 *
  * @ingroup payloads
 */
enum p2p_endpoint_type_t {
	
	NO_TYPE = 0,
	
	HOST = 1,
	
	SERVER_REFLEXIVE = 2,
	
	PEER_REFLEXIVE = 3,
	
	RELAYED = 4,
	
	MAX_TYPE = 5
	
};

/**
 * enum name for p2p_endpoint_type_t.
 *
 * @ingroup payloads
 */
extern enum_name_t *p2p_endpoint_type_names;

/**
 * @brief Class representing a P2P_ENDPOINT notify. In fact it's not
 * the notify per se, but the notification data of that notify that is
 * handled with this class.
 * 
 * @b Constructors:
 * - endpoint_notify_create()
 * - endpoint_notify_create_from_host()
 *
 * @ingroup payloads
 */
struct endpoint_notify_t {
	/**
	 * @brief Returns the priority of this endpoint.
	 * 
	 * @param this		object
	 * @return			priority
	 */
	u_int32_t (*get_priority) (endpoint_notify_t *this);
	
	/**
	 * @brief Sets the priority of this endpoint.
	 * 
	 * @param this		object
	 * @param priority	priority
	 */
	void (*set_priority) (endpoint_notify_t *this, u_int32_t priority);
	
	/**
	 * @brief Returns the endpoint type of this endpoint.
	 * 
	 * @param this		object
	 * @return			endpoint type
	 */
	p2p_endpoint_type_t (*get_type) (endpoint_notify_t *this);
	
	/**
	 * @brief Returns the endpoint family of this endpoint.
	 * 
	 * @param this		object
	 * @return			endpoint family
	 */
	p2p_endpoint_family_t (*get_family) (endpoint_notify_t *this);
	
	/**
	 * @brief Returns the host of this endpoint.
	 * 
	 * @param this		object
	 * @return			host
	 */
	host_t *(*get_host) (endpoint_notify_t *this);
	
	/**
	 * @brief Returns the base of this endpoint.
	 * 
	 * If this is not a SERVER_REFLEXIVE endpoint, the returned host is the same
	 * as the one returned by get_host.
	 * 
	 * @param this		object
	 * @return			host
	 */
	host_t *(*get_base) (endpoint_notify_t *this);
	
	/**
	 * @brief Generates a notification payload from this endpoint. 
	 * 	
	 * @param this 		object
	 * @return 			built notify_payload_t
	 */
	notify_payload_t *(*build_notify) (endpoint_notify_t *this);

	/**
	 * @brief Clones an endpoint_notify_t object.
	 *
	 * @param this 	endpoint_notify_t object to clone
	 * @return		cloned object
	 */
	endpoint_notify_t *(*clone) (endpoint_notify_t *this);
	
	/**
	 * @brief Destroys an endpoint_notify_t object.
	 *
	 * @param this 	endpoint_notify_t object to destroy
	 */
	void (*destroy) (endpoint_notify_t *this);
};

/**
 * @brief Creates an empty endpoint_notify_t object.
 * 
 * @return			created endpoint_notify_t object
 * 
 * @ingroup payloads
 */
endpoint_notify_t *endpoint_notify_create(void);


/**
 * @brief Creates an endpoint_notify_t object from a host.
 * 
 * @param type		the endpoint type
 * @param host		host to base the notify on (gets cloned)
 * @param base		base of the endpoint, applies only to reflexive endpoints (gets cloned)
 * @return			created endpoint_notify_t object
 * 
 * @ingroup payloads
 */
endpoint_notify_t *endpoint_notify_create_from_host(p2p_endpoint_type_t type, host_t *host, host_t *base);

/**
 * @brief Creates an endpoint_notify_t object from a notify payload.
 * 
 * @param notify	the notify payload
 * @return			- created endpoint_notify_t object
 * 					- NULL if invalid payload
 * @ingroup payloads
 */
endpoint_notify_t *endpoint_notify_create_from_payload(notify_payload_t *notify);

#endif /*ENDPOINT_NOTIFY_H_*/
