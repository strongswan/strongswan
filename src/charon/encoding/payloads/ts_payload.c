/**
 * @file ts_payload.c
 * 
 * @brief Implementation of ts_payload_t.
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

#include <stddef.h>

#include "ts_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>

typedef struct private_ts_payload_t private_ts_payload_t;

/**
 * Private data of an ts_payload_t object.
 * 
 */
struct private_ts_payload_t {
	/**
	 * Public ts_payload_t interface.
	 */
	ts_payload_t public;
	
	/**
	 * TRUE if this TS payload is of type TSi, FALSE for TSr.
	 */
	bool is_initiator;
	
	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;
	
	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;
	
	/**
	 * Number of traffic selectors
	 */
	u_int8_t number_of_traffic_selectors;
	
	/**
	 * Contains the traffic selectors of type traffic_selector_substructure_t.
	 */
	linked_list_t *traffic_selectors;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_ts_payload_t object
	 */
	void (*compute_length) (private_ts_payload_t *this);
};

/**
 * Encoding rules to parse or generate a TS payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_ts_payload_t.
 * 
 */
encoding_rule_t ts_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_ts_payload_t, next_payload) 				},
	/* the critical bit */
	{ FLAG,				offsetof(private_ts_payload_t, critical) 					},
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 																},
	{ RESERVED_BIT,	0 																},
	{ RESERVED_BIT,	0 																},
	{ RESERVED_BIT,	0 																},
	{ RESERVED_BIT,	0 																},
	{ RESERVED_BIT,	0 																},
	{ RESERVED_BIT,	0 																},
	/* Length of the whole payload*/	
	{ PAYLOAD_LENGTH,	offsetof(private_ts_payload_t, payload_length)},
 	/* 1 Byte TS type*/
	{ U_INT_8,			offsetof(private_ts_payload_t, number_of_traffic_selectors)	},
	/* 3 reserved bytes */
	{ RESERVED_BYTE,	0 															},
	{ RESERVED_BYTE,	0 															},
	{ RESERVED_BYTE,	0 															},
	/* some ts data bytes, length is defined in PAYLOAD_LENGTH */
	{ TRAFFIC_SELECTORS,	offsetof(private_ts_payload_t, traffic_selectors)		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Number of TSs !                 RESERVED                      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                       <Traffic Selectors>                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_ts_payload_t *this)
{
	iterator_t *iterator;
	status_t status = SUCCESS;
	
	if (this->number_of_traffic_selectors != (this->traffic_selectors->get_count(this->traffic_selectors)))
	{
		/* must be the same */
		return FAILED;
	}
	
	iterator = this->traffic_selectors->create_iterator(this->traffic_selectors,TRUE);
	while(iterator->has_next(iterator))
	{
		payload_t *current_traffic_selector;
		iterator->current(iterator,(void **)&current_traffic_selector);

		status = current_traffic_selector->verify(current_traffic_selector);
		if (status != SUCCESS)
		{
			break;
		}
	}
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implementation of ts_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_ts_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = ts_payload_encodings;
	*rule_count = sizeof(ts_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_ts_payload_t *this)
{
	if (this->is_initiator)
	{
		return TRAFFIC_SELECTOR_INITIATOR;
	}
	else
	{
		return TRAFFIC_SELECTOR_RESPONDER;
	}
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_ts_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_ts_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_ts_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implementation of ts_payload_t.get_initiator.
 */
static bool get_initiator (private_ts_payload_t *this)
{
	return (this->is_initiator);
}

/**
 * Implementation of ts_payload_t.set_initiator.
 */
static void set_initiator (private_ts_payload_t *this,bool is_initiator)
{
	this->is_initiator = is_initiator;
}

/**
 * Implementation of ts_payload_t.add_traffic_selector_substructure.
 */
static void add_traffic_selector_substructure (private_ts_payload_t *this,traffic_selector_substructure_t *traffic_selector)
{
	this->traffic_selectors->insert_last(this->traffic_selectors,traffic_selector);
	this->number_of_traffic_selectors = this->traffic_selectors->get_count(this->traffic_selectors);
}

/**
 * Implementation of ts_payload_t.create_traffic_selector_substructure_iterator.
 */
static iterator_t * create_traffic_selector_substructure_iterator (private_ts_payload_t *this, bool forward)
{
	return this->traffic_selectors->create_iterator(this->traffic_selectors,forward);
}

/**
 * Implementation of ts_payload_t.get_traffic_selectors.
 */
static linked_list_t *get_traffic_selectors(private_ts_payload_t *this)
{
	traffic_selector_t *ts;
	iterator_t *iterator;
	linked_list_t *ts_list = linked_list_create();
	
	iterator = this->traffic_selectors->create_iterator(this->traffic_selectors, TRUE);
	while (iterator->has_next(iterator))
	{
		traffic_selector_substructure_t *ts_substructure;
		iterator->current(iterator, (void**)&ts_substructure);
		ts = ts_substructure->get_traffic_selector(ts_substructure);
		ts_list->insert_last(ts_list, (void*)ts);
	}
	iterator->destroy(iterator);
	
	return ts_list;
}

/**
 * Implementation of private_ts_payload_t.compute_length.
 */
static void compute_length (private_ts_payload_t *this)
{
	iterator_t *iterator;
	size_t ts_count = 0;
	size_t length = TS_PAYLOAD_HEADER_LENGTH;
	iterator = this->traffic_selectors->create_iterator(this->traffic_selectors,TRUE);
	while (iterator->has_next(iterator))
	{
		payload_t * current_traffic_selector;
		iterator->current(iterator,(void **) &current_traffic_selector);
		length += current_traffic_selector->get_length(current_traffic_selector);
		ts_count++;
	}
	iterator->destroy(iterator);
	
	this->number_of_traffic_selectors= ts_count;
	this->payload_length = length;	

}


/**
 * Implementation of payload_t.destroy and ts_payload_t.destroy.
 */
static void destroy(private_ts_payload_t *this)
{
	while (this->traffic_selectors->get_count(this->traffic_selectors) > 0)
	{
		payload_t *current_traffic_selector;
		
		this->traffic_selectors->remove_last(this->traffic_selectors,(void **) &current_traffic_selector);
		
		current_traffic_selector->destroy(current_traffic_selector);
	}
	
	this->traffic_selectors->destroy(this->traffic_selectors);
		
	free(this);	
}

/*
 * Described in header
 */
ts_payload_t *ts_payload_create(bool is_initiator)
{
	private_ts_payload_t *this = malloc_thing(private_ts_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (ts_payload_t *)) destroy;
	this->public.get_initiator = (bool (*) (ts_payload_t *)) get_initiator;
	this->public.set_initiator = (void (*) (ts_payload_t *,bool)) set_initiator;
	this->public.add_traffic_selector_substructure = (void (*) (ts_payload_t *,traffic_selector_substructure_t *)) add_traffic_selector_substructure;
	this->public.create_traffic_selector_substructure_iterator = (iterator_t* (*) (ts_payload_t *,bool)) create_traffic_selector_substructure_iterator;
	this->public.get_traffic_selectors = (linked_list_t *(*) (ts_payload_t *)) get_traffic_selectors;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length =TS_PAYLOAD_HEADER_LENGTH;
	this->is_initiator = is_initiator;
	this->number_of_traffic_selectors = 0;
	this->traffic_selectors = linked_list_create();  

	return &(this->public);
}

/*
 * Described in header
 */
ts_payload_t *ts_payload_create_from_traffic_selectors(bool is_initiator, linked_list_t *traffic_selectors)
{
	iterator_t *iterator;
	traffic_selector_t *ts;
	traffic_selector_substructure_t *ts_substructure;
	private_ts_payload_t *this;
	
	this = (private_ts_payload_t*)ts_payload_create(is_initiator);
	
	iterator = traffic_selectors->create_iterator(traffic_selectors, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&ts);
		ts_substructure = traffic_selector_substructure_create_from_traffic_selector(ts);
		this->public.add_traffic_selector_substructure(&(this->public), ts_substructure);
	}
	iterator->destroy(iterator);
	
	return &(this->public);
}

