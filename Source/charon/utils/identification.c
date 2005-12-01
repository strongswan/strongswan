/**
 * @file identification.c
 * 
 * @brief Implementation of identification_t. 
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "identification.h"

#include <utils/allocator.h>


/** 
 * String mappings for id_type_t.
 */
mapping_t id_type_m[] = {
{ID_IPV4_ADDR, "ID_IPV4_ADDR"},
{ID_FQDN, "ID_FQDN"},
{ID_RFC822_ADDR, "ID_RFC822_ADDR"},
{ID_IPV6_ADDR, "ID_IPV6_ADDR"},
{ID_DER_ASN1_DN, "ID_DER_ASN1_DN"},
{ID_DER_ASN1_GN, "ID_DER_ASN1_GN"},
{ID_KEY_ID, "ID_KEY_ID"},
{MAPPING_END, NULL}
};



typedef struct private_identification_t private_identification_t;

/**
 * Private data of an identification_t object.
 */
struct private_identification_t {
	/**
	 * Public interface.
	 */
	identification_t public;
	
	/**
	 * string representation of this id
	 */
	char *string;
	
	/**
	 * encoded representation of this id
	 */
	chunk_t encoded;
	
	/**
	 * type of this id
	 */
	id_type_t type;
};

/**
 * implements identification_t.get_encoding
 */
static chunk_t get_encoding(private_identification_t *this)
{
	return this->encoded;
}

/**
 * implements identification_t.get_type
 */
static id_type_t get_type(private_identification_t *this)
{
	return this->type;
}
	
/**
 * implements identification_t.get_string
 */
static char *get_string(private_identification_t *this)
{
	return this->string;
}

/**
 * Implementation of identification_t.equals.
 */
static bool equals (private_identification_t *this,private_identification_t *other)
{
	if (this->type == other->type)
	{
		if (this->encoded.len != other->encoded.len)
		{
			return FALSE;
		}
		if (memcmp(this->encoded.ptr,other->encoded.ptr,this->encoded.len) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * implements identification_t.destroy
 */
static void destroy(private_identification_t *this)
{
	allocator_free(this->string);
	allocator_free(this->encoded.ptr);
	allocator_free(this);	
}

/**
 * Generic constructor used for the other twos
 */
static private_identification_t *identification_create()
{
	
	private_identification_t *this = allocator_alloc_thing(private_identification_t);
	
	/* assign methods */
	this->public.equals = (bool (*) (identification_t*,identification_t*))equals;
	this->public.get_encoding = (chunk_t (*) (identification_t*))get_encoding;
	this->public.get_type = (id_type_t (*) (identification_t*))get_type;
	this->public.get_string = (char* (*) (identification_t*))get_string;
	this->public.destroy = (void (*) (identification_t*))destroy;
	
	this->string = NULL;
	this->encoded = CHUNK_INITIALIZER;
	
	return this;
}

/*
 * Described in header.
 */
identification_t *identification_create_from_string(id_type_t type, char *string)
{
	private_identification_t *this = identification_create();
	this->type = type;
	switch (type)
	{
		case ID_IPV4_ADDR:
		{
			/* convert string */
			this->encoded.len = 4;
			this->encoded.ptr = allocator_alloc(this->encoded.len);
			if (inet_aton(string, ((struct in_addr*)(this->encoded.ptr))) == 0)
			{
				allocator_free(this->encoded.ptr);
				allocator_free(this);
				return NULL;
			}
			/* clone string */
			this->string = allocator_alloc(strlen(string)+1);
			strcpy(this->string, string);
			return &(this->public);
		}
		case ID_IPV6_ADDR:
		case ID_FQDN:
		case ID_RFC822_ADDR:
		case ID_DER_ASN1_DN:
		case ID_DER_ASN1_GN:
		case ID_KEY_ID:
		default:
		{
			/* not supported */
			allocator_free(this);
			return NULL;
		}
	}
}

/*
 * Described in header.
 */
identification_t *identification_create_from_encoding(id_type_t type, chunk_t encoded)
{
	private_identification_t *this = identification_create();
	this->type = type;
	switch (type)
	{
		case ID_IPV4_ADDR:
		{
			char *tmp;
			/* clone chunk */
			if (encoded.len != 4)
			{
				allocator_free(this);
				return NULL;	
			}
			this->encoded = allocator_clone_chunk(encoded);
			tmp = inet_ntoa(*((struct in_addr*)(encoded.ptr)));
			/* build string, must be cloned */
			this->string = allocator_alloc(strlen(tmp)+1);
			strcpy(this->string, tmp);
			return &(this->public);
		}
		case ID_IPV6_ADDR:
		case ID_FQDN:
		case ID_RFC822_ADDR:
		case ID_DER_ASN1_DN:
		case ID_DER_ASN1_GN:
		case ID_KEY_ID:
		default:
		{
			/* not supported */
			allocator_free(this);
			return NULL;
		}
	}
}
