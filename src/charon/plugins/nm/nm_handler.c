/*
 * Copyright (C) 2009 Martin Willi
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

#include "nm_handler.h"

#include <daemon.h>

typedef struct private_nm_handler_t private_nm_handler_t;

/**
 * Private data of an nm_handler_t object.
 */
struct private_nm_handler_t {
	
	/**
	 * Public nm_handler_t interface.
	 */
	nm_handler_t public;
	
	/**
	 * list of received DNS server attributes, pointer to 4 byte data
	 */
	linked_list_t *dns;
	
	/**
	 * list of received NBNS server attributes, pointer to 4 byte data
	 */
	linked_list_t *nbns;
};

/**
 * Implementation of attribute_handler_t.handle
 */
static bool handle(private_nm_handler_t *this, ike_sa_t *ike_sa,
				   configuration_attribute_type_t type, chunk_t data)
{
	linked_list_t *list;
	
	switch (type)
	{
		case INTERNAL_IP4_DNS:
			list = this->dns;
			break;
		case INTERNAL_IP4_NBNS:
			list = this->nbns;
			break;
		default:
			return FALSE;
	}
	if (data.len != 4)
	{
		return FALSE;
	}
	list->insert_last(list, chunk_clone(data).ptr);
	return TRUE;
}

/**
 * convert plain byte ptrs to handy chunk during enumeration
 */
static bool filter_chunks(void* null, char **in, chunk_t *out)
{
	*out = chunk_create(*in, 4);
	return TRUE;
}

/**
 * Implementation of nm_handler_t.create_enumerator
 */
static enumerator_t* create_enumerator(private_nm_handler_t *this,
									   configuration_attribute_type_t type)
{
	linked_list_t *list;
	
	switch (type)
	{
		case INTERNAL_IP4_DNS:
			list = this->dns;
			break;
		case INTERNAL_IP4_NBNS:
			list = this->nbns;
			break;
		default:
			return enumerator_create_empty();
	}
	return enumerator_create_filter(list->create_enumerator(list),
						(void*)filter_chunks, NULL, NULL);
}

/**
 * Implementation of nm_handler_t.reset
 */
static void reset(private_nm_handler_t *this)
{
	void *data;
	
	while (this->dns->remove_last(this->dns, (void**)&data) == SUCCESS)
	{
		free(data);
	}
	while (this->nbns->remove_last(this->nbns, (void**)&data) == SUCCESS)
	{
		free(data);
	}
}

/**
 * Implementation of nm_handler_t.destroy.
 */
static void destroy(private_nm_handler_t *this)
{
	reset(this);
	this->dns->destroy(this->dns);
	this->nbns->destroy(this->nbns);
	free(this);
}

/**
 * See header
 */
nm_handler_t *nm_handler_create()
{
	private_nm_handler_t *this = malloc_thing(private_nm_handler_t);
	
	this->public.handler.handle = (bool(*)(attribute_handler_t*, ike_sa_t*, configuration_attribute_type_t, chunk_t))handle;
	this->public.handler.release = (void(*)(attribute_handler_t*, ike_sa_t*, configuration_attribute_type_t, chunk_t))nop;
	this->public.create_enumerator = (enumerator_t*(*)(nm_handler_t*, configuration_attribute_type_t type))create_enumerator;
	this->public.reset = (void(*)(nm_handler_t*))reset;
	this->public.destroy = (void(*)(nm_handler_t*))destroy;
	
	this->dns = linked_list_create();
	this->nbns = linked_list_create();
	
	return &this->public;
}

