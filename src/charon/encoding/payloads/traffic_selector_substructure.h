/**
 * @file traffic_selector_substructure.h
 * 
 * @brief Interface of traffic_selector_substructure_t.
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


#ifndef TRAFFIC_SELECTOR_SUBSTRUCTURE_H_
#define TRAFFIC_SELECTOR_SUBSTRUCTURE_H_

#include <types.h>
#include <encoding/payloads/payload.h>
#include <utils/host.h>
#include <config/traffic_selector.h>

/**
 * Length of a TRAFFIC SELECTOR SUBSTRUCTURE without start and end address.
 * 
 * @ingroup payloads
 */
#define TRAFFIC_SELECTOR_HEADER_LENGTH 8

typedef struct traffic_selector_substructure_t traffic_selector_substructure_t;

/**
 * @brief Class representing an IKEv2 TRAFFIC SELECTOR.
 * 
 * The TRAFFIC SELECTOR format is described in RFC section 3.13.1.
 * 
 * @b Constructors:
 * - traffic_selector_substructure_create()
 * - traffic_selector_substructure_create_from_traffic_selector()
 * 
 * @ingroup payloads
 */
struct traffic_selector_substructure_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Get the type of Traffic selector.
	 *
	 * @param this 		calling traffic_selector_substructure_t object
	 * @return			type of traffic selector
	 *  
	 */
	ts_type_t (*get_ts_type) (traffic_selector_substructure_t *this);
	
	/**
	 * @brief Set the type of Traffic selector.
	 *
	 * @param this 		calling traffic_selector_substructure_t object
	 * @param ts_type	type of traffic selector	
	 */
	void (*set_ts_type) (traffic_selector_substructure_t *this,ts_type_t ts_type);
	
	/**
	 * @brief Get the IP protocol ID of Traffic selector.
	 *
	 * @param this 		calling traffic_selector_substructure_t object
	 * @return			type of traffic selector
	 *  
	 */
	u_int8_t (*get_protocol_id) (traffic_selector_substructure_t *this);
	
	/**
	 * @brief Set the IP protocol ID of Traffic selector
	 *
	 * @param this 			calling traffic_selector_substructure_t object
	 * @param protocol_id	protocol ID of traffic selector	
	 */
	void (*set_protocol_id) (traffic_selector_substructure_t *this,u_int8_t protocol_id);
	
	/**
	 * @brief Get the start port and address as host_t object.
	 *
	 * Returned host_t object has to get destroyed by the caller.
	 * 
	 * @param this 		calling traffic_selector_substructure_t object
	 * @return			start host as host_t object
	 *  
	 */
	host_t *(*get_start_host) (traffic_selector_substructure_t *this);
	
	/**
	 * @brief Set the start port and address as host_t object.
	 *
	 * @param this 			calling traffic_selector_substructure_t object
	 * @param start_host	start host as host_t object
	 */
	void (*set_start_host) (traffic_selector_substructure_t *this,host_t *start_host);
	
	/**
	 * @brief Get the end port and address as host_t object.
	 *
	 * Returned host_t object has to get destroyed by the caller.
	 * 
	 * @param this 		calling traffic_selector_substructure_t object
	 * @return			end host as host_t object
	 *  
	 */
	host_t *(*get_end_host) (traffic_selector_substructure_t *this);
	
	/**
	 * @brief Set the end port and address as host_t object.
	 *
	 * @param this 		calling traffic_selector_substructure_t object
	 * @param end_host	end host as host_t object
	 */
	void (*set_end_host) (traffic_selector_substructure_t *this,host_t *end_host);
	
	/**
	 * @brief Get a traffic_selector_t from this substructure.
	 *
	 * @warning traffic_selector_t must be destroyed after usage.
	 * 
	 * @param this 		calling traffic_selector_substructure_t object
	 * @return			contained traffic_selector_t
	 */
	traffic_selector_t *(*get_traffic_selector) (traffic_selector_substructure_t *this);
	
	/**
	 * @brief Destroys an traffic_selector_substructure_t object.
	 *
	 * @param this 	traffic_selector_substructure_t object to destroy
	 */
	void (*destroy) (traffic_selector_substructure_t *this);
};

/**
 * @brief Creates an empty traffic_selector_substructure_t object.
 *
 * TS type is set to default TS_IPV4_ADDR_RANGE!
 *  
 * @return 					traffic_selector_substructure_t object
 * 
 * @ingroup payloads
 */
traffic_selector_substructure_t *traffic_selector_substructure_create(void);

/**
 * @brief Creates an initialized traffif selector substructure using
 * the values from a traffic_selector_t.
 * 
 * @param traffic_selector	traffic_selector_t to use for initialization
 * @return					traffic_selector_substructure_t object
 * 
 * @ingroup payloads
 */
traffic_selector_substructure_t *traffic_selector_substructure_create_from_traffic_selector(traffic_selector_t *traffic_selector);


#endif /* /TRAFFIC_SELECTOR_SUBSTRUCTURE_H_ */
