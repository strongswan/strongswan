/**
 * @file configuration_attribute.c
 * 
 * @brief Implementation of configuration_attribute_t.
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

#include "configuration_attribute.h"

#include <encoding/payloads/encodings.h>
#include <types.h>


typedef struct private_configuration_attribute_t private_configuration_attribute_t;

/**
 * Private data of an configuration_attribute_t object.
 * 
 */
struct private_configuration_attribute_t {
	/**
	 * Public configuration_attribute_t interface.
	 */
	configuration_attribute_t public;
	
	/**
	 * Type of the attribute.
	 */
	u_int16_t attribute_type;
	
	/**
	 * Length of the attribute.
	 */
	u_int16_t attribute_length;
	

	/**
	 * Attribute value as chunk.
	 */
	chunk_t attribute_value;
};

/** 
 * String mappings for configuration_attribute_type_t.
 */
mapping_t configuration_attribute_type_m[] = {
	{INTERNAL_IP4_ADDRESS, "INTERNAL_IP4_ADDRESS"},
	{INTERNAL_IP4_NETMASK, "INTERNAL_IP4_NETMASK"},
	{INTERNAL_IP4_DNS, "INTERNAL_IP4_DNS"},
	{INTERNAL_IP4_NBNS, "INTERNAL_IP4_NBNS"},
	{INTERNAL_ADDRESS_EXPIRY, "INTERNAL_ADDRESS_EXPIRY"},
	{INTERNAL_IP4_DHCP, "INTERNAL_IP4_DHCP"},
	{APPLICATION_VERSION, "APPLICATION_VERSION"},
	{INTERNAL_IP6_ADDRESS, "INTERNAL_IP6_ADDRESS"},
	{INTERNAL_IP6_DNS, "INTERNAL_IP6_DNS"},
	{INTERNAL_IP6_NBNS, "INTERNAL_IP6_NBNS"},
	{INTERNAL_IP6_DHCP, "INTERNAL_IP6_DHCP"},
	{INTERNAL_IP4_SUBNET, "INTERNAL_IP4_SUBNET"},
	{SUPPORTED_ATTRIBUTES, "SUPPORTED_ATTRIBUTES"},
	{INTERNAL_IP6_SUBNET, "INTERNAL_IP6_SUBNET"},
	{MAPPING_END, NULL}
};


/**
 * Encoding rules to parse or generate a configuration attribute.
 * 
 * The defined offsets are the positions in a object of type 
 * private_configuration_attribute_t.
 * 
 */
encoding_rule_t configuration_attribute_encodings[] = {

	{ RESERVED_BIT,	0																					},
	/* type of the attribute as 15 bit unsigned integer */
	{ ATTRIBUTE_TYPE,			offsetof(private_configuration_attribute_t, attribute_type)				},	
	/* Length of attribute value */
	{ CONFIGURATION_ATTRIBUTE_LENGTH,		offsetof(private_configuration_attribute_t, attribute_length)},
	/* Value of attribute if attribute format flag is zero */
	{ CONFIGURATION_ATTRIBUTE_VALUE,		offsetof(private_configuration_attribute_t, attribute_value)}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !R|         Attribute Type      !            Length             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      ~                             Value                             ~
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_configuration_attribute_t *this)
{
	switch (this->attribute_type)
	{
         case INTERNAL_IP4_ADDRESS:
         case INTERNAL_IP4_NETMASK:
		 case INTERNAL_IP4_DNS:
		 case INTERNAL_IP4_NBNS:
		 case INTERNAL_ADDRESS_EXPIRY:
		 case INTERNAL_IP4_DHCP:
		 case APPLICATION_VERSION:
		 case INTERNAL_IP6_ADDRESS:
		 case INTERNAL_IP6_DNS:
		 case INTERNAL_IP6_NBNS:
		 case INTERNAL_IP6_DHCP:
		 case INTERNAL_IP4_SUBNET:
		 case SUPPORTED_ATTRIBUTES:
		 case INTERNAL_IP6_SUBNET:
		 {
		 	/* Attribute types are not checked in here */
		 	break;
		 }
		 default:
		 	return FAILED;
	}
	
	if (this->attribute_length != this->attribute_value.len)
	{
		return FAILED;
	}
	
	return SUCCESS;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_configuration_attribute_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = configuration_attribute_encodings;
	*rule_count = sizeof(configuration_attribute_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_configuration_attribute_t *this)
{
	return CONFIGURATION_ATTRIBUTE;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_configuration_attribute_t *this)
{
	return (NO_PAYLOAD);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_configuration_attribute_t *this,payload_type_t type)
{
}

/**
 * Implementation of configuration_attribute_t.get_length.
 */
static size_t get_length(private_configuration_attribute_t *this)
{
	return (this->attribute_value.len + CONFIGURATION_ATTRIBUTE_HEADER_LENGTH);
}

/**
 * Implementation of configuration_attribute_t.set_value.
 */
static void set_value(private_configuration_attribute_t *this, chunk_t value)
{
	if (this->attribute_value.ptr != NULL)
	{
		/* free existing value */
		chunk_free(&(this->attribute_value));		
	}
	
	this->attribute_value.ptr = clalloc(value.ptr,value.len);
	this->attribute_value.len = value.len;
	
	this->attribute_length = this->attribute_value.len;
}

/**
 * Implementation of configuration_attribute_t.get_value.
 */
static chunk_t get_value (private_configuration_attribute_t *this)
{
	return this->attribute_value;
}


/**
 * Implementation of configuration_attribute_t.set_attribute_type.
 */
static void set_attribute_type (private_configuration_attribute_t *this, u_int16_t type)
{
	this->attribute_type = type & 0x7FFF;
}

/**
 * Implementation of configuration_attribute_t.get_attribute_type.
 */
static u_int16_t get_attribute_type (private_configuration_attribute_t *this)
{
	return this->attribute_type;
}

/**
 * Implementation of configuration_attribute_t.get_attribute_length.
 */
static u_int16_t get_attribute_length (private_configuration_attribute_t *this)
{
	return this->attribute_length;
}


/**
 * Implementation of configuration_attribute_t.destroy and payload_t.destroy.
 */
static void destroy(private_configuration_attribute_t *this)
{
	if (this->attribute_value.ptr != NULL)
	{
		free(this->attribute_value.ptr);
	}	
	free(this);
}

/*
 * Described in header.
 */
configuration_attribute_t *configuration_attribute_create()
{
	private_configuration_attribute_t *this = malloc_thing(private_configuration_attribute_t);

	/* payload interface */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.set_value = (void (*) (configuration_attribute_t *,chunk_t)) set_value;
	this->public.get_value = (chunk_t (*) (configuration_attribute_t *)) get_value;
	this->public.set_attribute_type = (void (*) (configuration_attribute_t *,u_int16_t type)) set_attribute_type;
	this->public.get_attribute_type = (u_int16_t (*) (configuration_attribute_t *)) get_attribute_type;
	this->public.get_attribute_length = (u_int16_t (*) (configuration_attribute_t *)) get_attribute_length;
	this->public.destroy = (void (*) (configuration_attribute_t *)) destroy;
	
	/* set default values of the fields */
	this->attribute_type = 0;
	this->attribute_value = CHUNK_INITIALIZER;
	this->attribute_length = 0;

	return (&(this->public));
}
