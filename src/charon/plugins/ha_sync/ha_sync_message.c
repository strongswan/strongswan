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

#define _GNU_SOURCE
#include <string.h>
#include <arpa/inet.h>

#include "ha_sync_message.h"

#include <daemon.h>

#define ALLOCATION_BLOCK 64

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
	 * Allocated size of buf
	 */
	size_t allocated;

	/**
	 * Buffer containing encoded data
	 */
	chunk_t buf;
};

typedef struct ike_sa_id_encoding_t ike_sa_id_encoding_t;

/**
 * Encoding if an ike_sa_id_t
 */
struct ike_sa_id_encoding_t {
	u_int64_t initiator_spi;
	u_int64_t responder_spi;
	u_int8_t initiator;
} __attribute__((packed));

typedef struct identification_encoding_t identification_encoding_t;

/**
 * Encoding of a identification_t
 */
struct identification_encoding_t {
	u_int8_t type;
	u_int8_t len;
	char encoding[];
} __attribute__((packed));

typedef struct host_encoding_t host_encoding_t;

/**
 * encoding of a host_t
 */
struct host_encoding_t {
	u_int16_t port;
	u_int8_t family;
	char encoding[];
} __attribute__((packed));

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
	int increased = 0;

	while (this->buf.len + len > this->allocated)
	{	/* double size */
		this->allocated += ALLOCATION_BLOCK;
		increased++;
	}
	if (increased)
	{
		this->buf.ptr = realloc(this->buf.ptr, this->allocated);
	}
}

/**
 * Implementation of ha_sync_message_t.add_attribute
 */
static void add_attribute(private_ha_sync_message_t *this,
						  ha_sync_message_attribute_t attribute, ...)
{
	size_t len;
	va_list args;

	check_buf(this, sizeof(u_int8_t));
	this->buf.ptr[this->buf.len] = attribute;
	this->buf.len += sizeof(u_int8_t);

	va_start(args, attribute);
	switch (attribute)
	{
		/* ike_sa_id_t* */
		case HA_SYNC_IKE_ID:
		case HA_SYNC_IKE_REKEY_ID:
		{
			ike_sa_id_encoding_t *enc;
			ike_sa_id_t *id;

			id = va_arg(args, ike_sa_id_t*);
			check_buf(this, sizeof(ike_sa_id_encoding_t));
			enc = (ike_sa_id_encoding_t*)(this->buf.ptr + this->buf.len);
			this->buf.len += sizeof(ike_sa_id_encoding_t);
			enc->initiator = id->is_initiator(id);
			enc->initiator_spi = id->get_initiator_spi(id);
			enc->responder_spi = id->get_responder_spi(id);
			break;
		}
		/* identification_t* */
		case HA_SYNC_LOCAL_ID:
		case HA_SYNC_REMOTE_ID:
		case HA_SYNC_EAP_ID:
		{
			identification_encoding_t *enc;
			identification_t *id;
			chunk_t data;

			id = va_arg(args, identification_t*);
			data = id->get_encoding(id);
			check_buf(this, sizeof(identification_encoding_t) + data.len);
			enc = (identification_encoding_t*)(this->buf.ptr + this->buf.len);
			this->buf.len += sizeof(identification_encoding_t) + data.len;
			enc->type = id->get_type(id);
			enc->len = data.len;
			memcpy(enc->encoding, data.ptr, data.len);
			break;
		}
		/* host_t* */
		case HA_SYNC_LOCAL_ADDR:
		case HA_SYNC_REMOTE_ADDR:
		case HA_SYNC_LOCAL_VIP:
		case HA_SYNC_REMOTE_VIP:
		case HA_SYNC_ADDITIONAL_ADDR:
		{
			host_encoding_t *enc;
			host_t *host;
			chunk_t data;

			host = va_arg(args, host_t*);
			data = host->get_address(host);
			check_buf(this, sizeof(host_encoding_t) + data.len);
			enc = (host_encoding_t*)(this->buf.ptr + this->buf.len);
			this->buf.len += sizeof(host_encoding_t) + data.len;
			enc->family = host->get_family(host);
			enc->port = htons(host->get_port(host));
			memcpy(enc->encoding, data.ptr, data.len);
			break;
		}
		/* char* */
		case HA_SYNC_CONFIG_NAME:
		{
			char *str;

			str = va_arg(args, char*);
			len = strlen(str) + 1;
			check_buf(this, len);
			memcpy(this->buf.ptr + this->buf.len, str, len);
			this->buf.len += len;
			break;
		}
		/* u_int16_t */
		case HA_SYNC_ALG_PRF:
		case HA_SYNC_ALG_ENCR:
		case HA_SYNC_ALG_ENCR_LEN:
		case HA_SYNC_ALG_INTEG:
		{
			u_int16_t val;

			val = (u_int16_t)va_arg(args, u_int32_t);
			check_buf(this, sizeof(val));
			*(u_int16_t*)(this->buf.ptr + this->buf.len) = htons(val);
			this->buf.len += sizeof(val);
			break;
		}
		/** u_int32_t */
		case HA_SYNC_CONDITIONS:
		case HA_SYNC_EXTENSIONS:
		{
			u_int32_t val;

			val = va_arg(args, u_int32_t);
			check_buf(this, sizeof(val));
			*(u_int32_t*)(this->buf.ptr + this->buf.len) = htonl(val);
			this->buf.len += sizeof(val);
			break;
		}
		/** chunk_t */
		case HA_SYNC_NONCE_I:
		case HA_SYNC_NONCE_R:
		case HA_SYNC_SECRET:
		{
			chunk_t chunk;

			chunk = va_arg(args, chunk_t);
			check_buf(this, chunk.len + sizeof(u_int16_t));
			*(u_int16_t*)(this->buf.ptr + this->buf.len) = htons(chunk.len);
			memcpy(this->buf.ptr + this->buf.len + sizeof(u_int16_t),
				   chunk.ptr, chunk.len);
			this->buf.len += chunk.len + sizeof(u_int16_t);;
			break;
		}
		default:
		{
			DBG1(DBG_CFG, "unable to encode, attribute %d unknown", attribute);
			this->buf.len -= sizeof(u_int8_t);
			break;
		}
	}
	va_end(args);
}

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implementes enumerator_t */
	enumerator_t public;
	/** position in message */
	chunk_t buf;
	/** cleanup handler of current element, if any */
	void (*cleanup)(void* data);
	/** data to pass to cleanup handler */
	void *cleanup_data;
} attribute_enumerator_t;

/**
 * Implementation of create_attribute_enumerator().enumerate
 */
static bool attribute_enumerate(attribute_enumerator_t *this,
								ha_sync_message_attribute_t *attr_out,
								ha_sync_message_value_t *value)
{
	ha_sync_message_attribute_t attr;

	if (this->cleanup)
	{
		this->cleanup(this->cleanup_data);
		this->cleanup = NULL;
	}
	if (this->buf.len < 1)
	{
		return FALSE;
	}
	attr = this->buf.ptr[0];
	this->buf = chunk_skip(this->buf, 1);
	switch (attr)
	{
		/* ike_sa_id_t* */
		case HA_SYNC_IKE_ID:
		case HA_SYNC_IKE_REKEY_ID:
		{
			ike_sa_id_encoding_t *enc;

			if (this->buf.len < sizeof(ike_sa_id_encoding_t))
			{
				return FALSE;
			}
			enc = (ike_sa_id_encoding_t*)(this->buf.ptr);
			value->ike_sa_id = ike_sa_id_create(enc->initiator_spi,
											enc->responder_spi, enc->initiator);
			*attr_out = attr;
			this->cleanup = (void*)value->ike_sa_id->destroy;
			this->cleanup_data = value->ike_sa_id;
			this->buf = chunk_skip(this->buf, sizeof(ike_sa_id_encoding_t));
			return TRUE;
		}
		/* identification_t* */
		case HA_SYNC_LOCAL_ID:
		case HA_SYNC_REMOTE_ID:
		case HA_SYNC_EAP_ID:
		{
			identification_encoding_t *enc;

			enc = (identification_encoding_t*)(this->buf.ptr);
			if (this->buf.len < sizeof(identification_encoding_t) ||
				this->buf.len < sizeof(identification_encoding_t) + enc->len)
			{
				return FALSE;
			}
			value->id = identification_create_from_encoding(enc->type,
										chunk_create(enc->encoding, enc->len));
			*attr_out = attr;
			this->cleanup = (void*)value->id->destroy;
			this->cleanup_data = value->id;
			this->buf = chunk_skip(this->buf,
								sizeof(identification_encoding_t) + enc->len);
			return TRUE;
		}
		/* host_t* */
		case HA_SYNC_LOCAL_ADDR:
		case HA_SYNC_REMOTE_ADDR:
		case HA_SYNC_LOCAL_VIP:
		case HA_SYNC_REMOTE_VIP:
		case HA_SYNC_ADDITIONAL_ADDR:
		{
			host_encoding_t *enc;

			enc = (host_encoding_t*)(this->buf.ptr);
			if (this->buf.len < sizeof(host_encoding_t))
			{
				return FALSE;
			}
			value->host = host_create_from_chunk(enc->family,
									chunk_create(enc->encoding,
										this->buf.len - sizeof(host_encoding_t)),
									ntohs(enc->port));
			if (!value->host)
			{
				return FALSE;
			}
			*attr_out = attr;
			this->cleanup = (void*)value->host->destroy;
			this->cleanup_data = value->host;
			this->buf = chunk_skip(this->buf, sizeof(host_encoding_t) +
								   value->host->get_address(value->host).len);
			return TRUE;
		}
		/* char* */
		case HA_SYNC_CONFIG_NAME:
		{
			size_t len;

			len = strnlen(this->buf.ptr, this->buf.len);
			if (len >= this->buf.len)
			{
				return FALSE;
			}
			value->str = this->buf.ptr;
			*attr_out = attr;
			this->buf = chunk_skip(this->buf, len + 1);
			return TRUE;
		}
		/** u_int16_t */
		case HA_SYNC_ALG_PRF:
		case HA_SYNC_ALG_ENCR:
		case HA_SYNC_ALG_ENCR_LEN:
		case HA_SYNC_ALG_INTEG:
		{
			if (this->buf.len < sizeof(u_int16_t))
			{
				return FALSE;
			}
			value->u16 = ntohs(*(u_int16_t*)this->buf.ptr);
			*attr_out = attr;
			this->buf = chunk_skip(this->buf, sizeof(u_int16_t));
			return TRUE;
		}
		/** u_int32_t */
		case HA_SYNC_CONDITIONS:
		case HA_SYNC_EXTENSIONS:
		{
			if (this->buf.len < sizeof(u_int32_t))
			{
				return FALSE;
			}
			value->u32 = ntohl(*(u_int32_t*)this->buf.ptr);
			*attr_out = attr;
			this->buf = chunk_skip(this->buf, sizeof(u_int32_t));
			return TRUE;
		}
		/** chunk_t */
		case HA_SYNC_NONCE_I:
		case HA_SYNC_NONCE_R:
		case HA_SYNC_SECRET:
		{
			size_t len;

			if (this->buf.len < sizeof(u_int16_t))
			{
				return FALSE;
			}
			len = ntohs(*(u_int16_t*)this->buf.ptr);
			this->buf = chunk_skip(this->buf, sizeof(u_int16_t));
			if (this->buf.len < len)
			{
				return FALSE;
			}
			value->chunk.len = len;
			value->chunk.ptr = this->buf.ptr;
			*attr_out = attr;
			this->buf = chunk_skip(this->buf, len);
			return TRUE;
		}
		default:
		{
			return FALSE;
		}
	}
}

/**
 * Implementation of create_attribute_enumerator().destroy
 */
static void enum_destroy(attribute_enumerator_t *this)
{
	if (this->cleanup)
	{
		this->cleanup(this->cleanup_data);
	}
	free(this);
}

/**
 * Implementation of ha_sync_message_t.create_attribute_enumerator
 */
static enumerator_t* create_attribute_enumerator(private_ha_sync_message_t *this)
{
	attribute_enumerator_t *e = malloc_thing(attribute_enumerator_t);

	e->public.enumerate = (void*)attribute_enumerate;
	e->public.destroy = (void*)enum_destroy;

	e->buf = chunk_skip(this->buf, 2);
	e->cleanup = NULL;
	e->cleanup_data = NULL;

	return &e->public;
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

	this->allocated = ALLOCATION_BLOCK;
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

