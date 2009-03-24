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
 *
 * $Id$
 */

/**
 * @defgroup ts_payload ts_payload
 * @{ @ingroup payloads
 */


#ifndef TS_PAYLOAD_H_
#define TS_PAYLOAD_H_

typedef struct ts_payload_t ts_payload_t;

#include <library.h>
#include <utils/linked_list.h>
#include <config/traffic_selector.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/traffic_selector_substructure.h>

/**
 * Length of a TS payload without the Traffic selectors.
 */
#define TS_PAYLOAD_HEADER_LENGTH 8


/**
 * Class representing an IKEv2 TS payload.
 *
 * The TS payload format is described in RFC section 3.13.
 */
struct ts_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * Get the type of TSpayload (TSi or TSr).
	 *
	 * @return
	 * 						- TRUE if this payload is of type TSi
	 * 						- FALSE if this payload is of type TSr
	 */
	bool (*get_initiator) (ts_payload_t *this);
	
	/**
	 * Set the type of TS payload (TSi or TSr).
	 *
	 * @param is_initiator	
	 * 						- TRUE if this payload is of type TSi
	 * 						- FALSE if this payload is of type TSr
	 */
	void (*set_initiator) (ts_payload_t *this,bool is_initiator);
	
	/**
	 * Adds a traffic_selector_substructure_t object to this object.
	 *
	 * @param traffic_selector  traffic_selector_substructure_t object to add
	 */
	void (*add_traffic_selector_substructure) (ts_payload_t *this,
							traffic_selector_substructure_t *traffic_selector);
	
	/**
	 * Creates an iterator of stored traffic_selector_substructure_t objects.
	 * 
	 * When removing an traffic_selector_substructure_t object 
	 * using this iterator, the length of this payload 
	 * has to get refreshed by calling payload_t.get_length!
	 *
	 * @param forward 		iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t *(*create_traffic_selector_substructure_iterator) (
											ts_payload_t *this, bool forward);
	
	/**
	 * Get a list of nested traffic selectors as traffic_selector_t.
	 * 
	 * Resulting list and its traffic selectors must be destroyed after usage
	 *
	 * @return				list of traffic selectors
	 */
	linked_list_t *(*get_traffic_selectors) (ts_payload_t *this);

	/**
	 * Destroys an ts_payload_t object.
	 */
	void (*destroy) (ts_payload_t *this);
};

/**
 * Creates an empty ts_payload_t object.
 * 
 * @param is_initiator	
 * 						- TRUE if this payload is of type TSi
 * 						- FALSE if this payload is of type TSr
 * @return				ts_payload_t object
 */
ts_payload_t *ts_payload_create(bool is_initiator);

/**
 * Creates ts_payload with a list of traffic_selector_t
 * 
 * @param is_initiator	
 * 							- TRUE if this payload is of type TSi
 * 							- FALSE if this payload is of type TSr
 * @param traffic_selectors	list of traffic selectors to include
 * @return					ts_payload_t object
 */
ts_payload_t *ts_payload_create_from_traffic_selectors(bool is_initiator, 
											linked_list_t *traffic_selectors);

#endif /** TS_PAYLOAD_H_ @}*/
