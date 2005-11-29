/**
 * @file ts_payload.h
 * 
 * @brief Interface of ts_payload_t.
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


#ifndef TS_PAYLOAD_H_
#define TS_PAYLOAD_H_

#include <types.h>
#include <utils/iterator.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/traffic_selector_substructure.h>

/**
 * Length of a TS payload without the Traffic selectors.
 * 
 * @ingroup payloads
 */
#define TS_PAYLOAD_HEADER_LENGTH 8


typedef struct ts_payload_t ts_payload_t;

/**
 * Object representing an IKEv2 TS payload.
 * 
 * The TS payload format is described in draft section 3.13.
 * 
 * @ingroup payloads
 * 
 */
struct ts_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Get the type of TSpayload (TSi or TSr).
	 *
	 * @param this 			calling id_payload_t object
	 * @return
	 * 						- TRUE if this payload is of type TSi
	 * 						- FALSE if this payload is of type TSr
	 * 
	 */
	bool (*get_initiator) (ts_payload_t *this);
	
	/**
	 * @brief Set the type of TS payload (TSi or TSr).
	 *
	 * @param this 			calling id_payload_t object
	 * @param is_initiator	
	 * 						- TRUE if this payload is of type TSi
	 * 						- FALSE if this payload is of type TSr
	 * 
	 */
	void (*set_initiator) (ts_payload_t *this,bool is_initiator);
	
	/**
	 * @brief Adds a traffic_selector_substructure_t object to this object.
	 * 
	 * @warning The added traffic_selector_substructure_t object  is 
	 * 			getting destroyed in destroy function of ts_payload_t.
	 *
	 * @param this 				calling ts_payload_t object
	 * @param traffic_selector  traffic_selector_substructure_t object to add
	 */
	void (*add_traffic_selector_substructure) (ts_payload_t *this,traffic_selector_substructure_t *traffic_selector);
	
	/**
	 * @brief Creates an iterator of stored traffic_selector_substructure_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 * 
	 * @warning When removing an traffic_selector_substructure_t object 
	 * 			using this iterator, the length of this payload 
	 * 			has to get refreshed by calling payload_t.get_length!
	 *
	 * @param this 			calling ts_payload_t object
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t *(*create_traffic_selector_substructure_iterator) (ts_payload_t *this, bool forward);

	/**
	 * @brief Destroys an ts_payload_t object.
	 *
	 * @param this 	ts_payload_t object to destroy
	 */
	void (*destroy) (ts_payload_t *this);
};

/**
 * @brief Creates an empty id_payload_t object.
 * 
 * 
 * @param is_initiator	
 * 						- TRUE if this payload is of type TSi
 * 						- FALSE if this payload is of type TSr
 * 
 * @return				created id_payload_t object
 * 
 * @ingroup payloads
 */
ts_payload_t *ts_payload_create(bool is_initiator);


#endif //TS_PAYLOAD_H_
