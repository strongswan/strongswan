/*
 * Copyright (C) 2008 Martin Willi
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

#include "ha_sync_message.h"

#include <arpa/inet.h>

#include <daemon.h>

typedef struct private_ha_sync_message_t private_ha_sync_message_t;

/**
 * Private data of an ha_sync_message_t object.
 */
struct private_ha_sync_message_t {

	/**
	 * Public ha_sync_message_t interface.
	 */
	ha_sync_message_t public;

	/**
	 * Number of bytes allocted in buffer
	 */
	size_t allocated;

	/**
	 * Buffer containing encoded data
	 */
	chunk_t buf;
};

/**
 * Implementation of ha_sync_message_t.get_type
 */
static ha_sync_message_type_t get_type(private_ha_sync_message_t *this)
{
	return this->buf.ptr[1];
}

/**
 * check for space in buffer, increase if necessary
 */
static void check_buf(private_ha_sync_message_t *this, size_t len)
{
	while (this->buf.len + len > this->allocated)
	{	/* double size */
		this->allocated = this->allocated * 2;
		this->buf.ptr = realloc(this->buf.ptr, this->allocated);
	}
}

/**
 * Implementation of ha_sync_message_t.add_attribute
 */
static void add_attribute(private_ha_sync_message_t *this,
						  ha_sync_message_attribute_t attribute,
						  ha_sync_message_value_t value)
{
	size_t len;

	check_buf(this, sizeof(u_int8_t));
	this->buf.ptr[this->buf.len] = attribute;
	this->buf.len += sizeof(u_int8_t);

	switch (attribute)
	{
		case HA_SYNC_ENCAP_U8:
		case HA_SYNC_MODE_U8:
		case HA_SYNC_IPCOMP_U8:
			check_buf(this, sizeof(value.u8));
			this->buf.ptr[this->buf.len] = value.u8;
			this->buf.len += sizeof(value.u8);
			break;
		case HA_SYNC_PORT_L_U16:
		case HA_SYNC_PORT_R_U16:
		case HA_SYNC_CPI_L_U16:
		case HA_SYNC_CPI_R_U16:
		case HA_SYNC_ALG_INTEG_U16:
		case HA_SYNC_ALG_ENC_U16:
			check_buf(this, sizeof(value.u16));
			this->buf.ptr[this->buf.len] = htons(value.u16);
			this->buf.len += sizeof(value.u16);
			break;
		case HA_SYNC_SPI_L_U32:
		case HA_SYNC_SPI_R_U32:
			check_buf(this, sizeof(value.u32));
			this->buf.ptr[this->buf.len] = htonl(value.u32);
			this->buf.len += sizeof(value.u32);
			break;
		case HA_SYNC_IPV4_L_CHNK:
		case HA_SYNC_IPV4_R_CHNK:
		case HA_SYNC_NONCE_I_CHNK:
		case HA_SYNC_NONCE_R_CHNK:
		case HA_SYNC_SECRET_CHNK:
			check_buf(this, value.chnk.len);
			memcpy(this->buf.ptr + this->buf.len, value.chnk.ptr, value.chnk.len);
			this->buf.len += value.chnk.len;
			break;
		case HA_SYNC_CONFIG_STR:
			len = strlen(value.str) + 1;
			check_buf(this, len);
			memcpy(this->buf.ptr + this->buf.len, value.str, len);
			this->buf.len += len;
			break;
		default:
			DBG1(DBG_CFG, "unable to encode, attribute %d unknown", attribute);
			this->buf.len -= sizeof(u_int8_t);
			break;
	}
}

/**
 * Implementation of ha_sync_message_t.create_attribute_enumerator
 */
static enumerator_t* create_attribute_enumerator(private_ha_sync_message_t *this)
{
	return enumerator_create_empty();
}

/**
 * Implementation of ha_sync_message_t.get_encoding
 */
static chunk_t get_encoding(private_ha_sync_message_t *this)
{
	return this->buf;
}

/**
 * Implementation of ha_sync_message_t.destroy.
 */
static void destroy(private_ha_sync_message_t *this)
{
	free(this->buf.ptr);
	free(this);
}


static private_ha_sync_message_t *ha_sync_message_create_generic()
{
	private_ha_sync_message_t *this = malloc_thing(private_ha_sync_message_t);

	this->public.get_type = (ha_sync_message_type_t(*)(ha_sync_message_t*))get_type;
	this->public.add_attribute = (void(*)(ha_sync_message_t*, ha_sync_message_attribute_t attribute, ...))add_attribute;
	this->public.create_attribute_enumerator = (enumerator_t*(*)(ha_sync_message_t*))create_attribute_enumerator;
	this->public.get_encoding = (chunk_t(*)(ha_sync_message_t*))get_encoding;
	this->public.destroy = (void(*)(ha_sync_message_t*))destroy;

	return this;
}

/**
 * See header
 */
ha_sync_message_t *ha_sync_message_create(ha_sync_message_type_t type)
{
	private_ha_sync_message_t *this = ha_sync_message_create_generic();

	this->allocated = 64;
	this->buf.ptr = malloc(this->allocated);
	this->buf.len = 2;
	this->buf.ptr[0] = HA_SYNC_MESSAGE_VERSION;
	this->buf.ptr[1] = type;

	return &this->public;
}

/**
 * See header
 */
ha_sync_message_t *ha_sync_message_parse(chunk_t data)
{
	private_ha_sync_message_t *this;

	if (data.len < 2)
	{
		DBG1(DBG_CFG, "HA sync message too short");
		return NULL;
	}
	if (data.ptr[0] != HA_SYNC_MESSAGE_VERSION)
	{
		DBG1(DBG_CFG, "HA sync message has version %d, expected %d",
			 data.ptr[0], HA_SYNC_MESSAGE_VERSION);
		return NULL;
	}

	this = ha_sync_message_create_generic();
	this->buf = chunk_clone(data);
	this->allocated = this->buf.len;

	return &this->public;
}

