/**
 * @file traffic_selector.h
 * 
 * @brief Interface of traffic_selector_t.
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

#ifndef _TRAFFIC_SELECTOR_H_
#define _TRAFFIC_SELECTOR_H_

#include <types.h>
#include <encoding/payloads/traffic_selector_substructure.h>


typedef struct traffic_selector_t traffic_selector_t;

/**
 * @brief 
 *
 * 
 * @ingroup config
 */
struct traffic_selector_t {
	
	traffic_selector_t *(*get_subset) (traffic_selector_t *this, traffic_selector_t *other);
	
	traffic_selector_t *(*clone) (traffic_selector_t *this);
	
	chunk_t (*get_from_address) (traffic_selector_t *this);
	
	chunk_t (*get_to_address) (traffic_selector_t *this);
	
	u_int16_t (*get_from_port) (traffic_selector_t *this);
	
	u_int16_t (*get_to_port) (traffic_selector_t *this);
	
	/**
	 * @brief Destroys the config object
	 * 
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (traffic_selector_t *this);
};

/**
 * @brief 
 * 
 * @return 		created traffic_selector_t
 * 
 * @ingroup config
 */
traffic_selector_t *traffic_selector_create_from_string(u_int8_t protocol, ts_type_t type, char *from_addr, u_int16_t from_port, char *to_addr, u_int16_t to_port);

traffic_selector_t *traffic_selector_create_from_bytes(u_int8_t protocol, ts_type_t type, chunk_t from_address, int16_t from_port, chunk_t to_address, u_int16_t to_port);

#endif //_TRAFFIC_SELECTOR_H_


