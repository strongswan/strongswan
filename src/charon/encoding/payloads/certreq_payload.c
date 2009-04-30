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

#include <daemon.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/cert_payload.h>

#include "certreq_payload.h"


typedef struct private_certreq_payload_t private_certreq_payload_t;

/**
 * Private data of an certreq_payload_t object.
 * 
 */
struct private_certreq_payload_t {
	/**
	 * Public certreq_payload_t interface.
	 */
	certreq_payload_t public;
	
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
	 * Encoding of the CERT Data.
	 */
	u_int8_t encoding;
	
	/**
	 * The contained certreq data value.
	 */
	chunk_t data;
};

/**
 * Encoding rules to parse or generate a CERTREQ payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_certreq_payload_t.
 * 
 */
encoding_rule_t certreq_payload_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_certreq_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_certreq_payload_t, critical) 		},
	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	{ RESERVED_BIT,	0 														},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_certreq_payload_t, payload_length)	},
	/* 1 Byte CERTREQ type*/
	{ U_INT_8,			offsetof(private_certreq_payload_t, encoding)		},
	/* some certreq data bytes, length is defined in PAYLOAD_LENGTH */
	{ CERTREQ_DATA,		offsetof(private_certreq_payload_t, data)			}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Cert Encoding !                                               !
      +-+-+-+-+-+-+-+-+                                               !
      ~                    Certification Authority                    ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_certreq_payload_t *this)
{
	if (this->encoding == ENC_X509_SIGNATURE)
	{
		if (this->data.len < HASH_SIZE_SHA1 ||
			this->data.len % HASH_SIZE_SHA1)
		{
			DBG1(DBG_ENC, "invalid X509 hash length (%d) in certreq",
				 this->data.len);
			return FAILED;
		}
	}
	return SUCCESS;
}

/**
 * Implementation of certreq_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_certreq_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = certreq_payload_encodings;
	*rule_count = sizeof(certreq_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_certreq_payload_t *this)
{
	return CERTIFICATE_REQUEST;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_certreq_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_certreq_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_certreq_payload_t *this)
{
	return this->payload_length;
}
	
/**
 * Implementation of certreq_payload_t.add_keyid.
 */
static void add_keyid(private_certreq_payload_t *this, chunk_t keyid)
{
	this->data = chunk_cat("mc", this->data, keyid);
	this->payload_length += keyid.len;
}

typedef struct keyid_enumerator_t keyid_enumerator_t;

/**
 * enumerator to enumerate keyids
 */
struct keyid_enumerator_t  {
	enumerator_t public;
	chunk_t full;
	u_char *pos;
};

/**
 * enumerate function for keyid_enumerator
 */
static bool keyid_enumerate(keyid_enumerator_t *this, chunk_t *chunk)
{
	if (this->pos == NULL)
	{
		this->pos = this->full.ptr;
	}
	else
	{
		this->pos += HASH_SIZE_SHA1;
		if (this->pos > (this->full.ptr + this->full.len - HASH_SIZE_SHA1))
		{
			this->pos = NULL;
		}
	}
	if (this->pos)
	{
		chunk->ptr = this->pos;
		chunk->len = HASH_SIZE_SHA1;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of certreq_payload_t.create_keyid_enumerator.
 */
static enumerator_t* create_keyid_enumerator(private_certreq_payload_t *this)
{
	keyid_enumerator_t *enumerator = malloc_thing(keyid_enumerator_t);
	enumerator->public.enumerate = (void*)keyid_enumerate;
	enumerator->public.destroy = (void*)free;
	enumerator->full = this->data;
	enumerator->pos = NULL;
	return &enumerator->public;
}

/**
 * Implementation of certreq_payload_t.get_cert_type.
 */
static certificate_type_t get_cert_type(private_certreq_payload_t *this)
{
	switch (this->encoding)
	{
		case ENC_X509_SIGNATURE:
			return CERT_X509;
		default:
			return CERT_ANY;
	}
}

/**
 * Implementation of payload_t.destroy and certreq_payload_t.destroy.
 */
static void destroy(private_certreq_payload_t *this)
{
	chunk_free(&this->data);
	free(this);	
}

/*
 * Described in header
 */
certreq_payload_t *certreq_payload_create()
{
	private_certreq_payload_t *this = malloc_thing(private_certreq_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t*))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t*,encoding_rule_t**,size_t*))get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t*))get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t*))get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t*,payload_type_t))set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t*))get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t*))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (certreq_payload_t*)) destroy;
	this->public.create_keyid_enumerator = (enumerator_t*(*)(certreq_payload_t*))create_keyid_enumerator;
		this->public.get_cert_type = (certificate_type_t(*)(certreq_payload_t*))get_cert_type;
	this->public.add_keyid = (void(*)(certreq_payload_t*, chunk_t keyid))add_keyid;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = CERTREQ_PAYLOAD_HEADER_LENGTH;
	this->data = chunk_empty;
	this->encoding = 0;

	return &this->public;
}

/*
 * Described in header
 */
certreq_payload_t *certreq_payload_create_type(certificate_type_t type)
{
	private_certreq_payload_t *this = (private_certreq_payload_t*)certreq_payload_create();
	
	switch (type)
	{
		case CERT_X509:
			this->encoding = ENC_X509_SIGNATURE;
			break;
		default:
			DBG1(DBG_ENC, "certificate type %N not supported in requests",
				 certificate_type_names, type);
			free(this);
			return NULL;
	}
	return &this->public;
}

