/**
 * @file certreq_payload.c
 * 
 * @brief Implementation of certreq_payload_t.
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
	u_int8_t cert_encoding;
	
	/**
	 * The contained certreq data value.
	 */
	chunk_t certreq_data;
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
	{ PAYLOAD_LENGTH,	offsetof(private_certreq_payload_t, payload_length)},
	/* 1 Byte CERTREQ type*/
	{ U_INT_8,			offsetof(private_certreq_payload_t, cert_encoding)},
	/* some certreq data bytes, length is defined in PAYLOAD_LENGTH */
	{ CERTREQ_DATA,			offsetof(private_certreq_payload_t, certreq_data)}
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
	if ((this->cert_encoding == 0) ||
		((this->cert_encoding >= 14) && (this->cert_encoding <= 200)))
	{
		/* reserved IDs */
		return FAILED;
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
 * Implementation of certreq_payload_t.set_cert_encoding.
 */
static void set_cert_encoding (private_certreq_payload_t *this, cert_encoding_t encoding)
{
	this->cert_encoding = encoding;
}

/**
 * Implementation of certreq_payload_t.get_cert_encoding.
 */
static cert_encoding_t get_cert_encoding (private_certreq_payload_t *this)
{
	return (this->cert_encoding);
}

/**
 * Implementation of certreq_payload_t.set_data.
 */
static void set_data (private_certreq_payload_t *this, chunk_t data)
{
	if (this->certreq_data.ptr != NULL)
	{
		chunk_free(&(this->certreq_data));
	}
	this->certreq_data.ptr = clalloc(data.ptr,data.len);
	this->certreq_data.len = data.len;
	this->payload_length = CERTREQ_PAYLOAD_HEADER_LENGTH + this->certreq_data.len;
}

/**
 * Implementation of certreq_payload_t.get_data.
 */
static chunk_t get_data (private_certreq_payload_t *this)
{
	return (this->certreq_data);
}

/**
 * Implementation of certreq_payload_t.get_data_clone.
 */
static chunk_t get_data_clone (private_certreq_payload_t *this)
{
	chunk_t cloned_data;
	if (this->certreq_data.ptr == NULL)
	{
		return (this->certreq_data);
	}
	cloned_data.ptr = clalloc(this->certreq_data.ptr,this->certreq_data.len);
	cloned_data.len = this->certreq_data.len;
	return cloned_data;
}

/**
 * Implementation of payload_t.destroy and certreq_payload_t.destroy.
 */
static void destroy(private_certreq_payload_t *this)
{
	if (this->certreq_data.ptr != NULL)
	{
		chunk_free(&(this->certreq_data));
	}
	
	free(this);	
}

/*
 * Described in header
 */
certreq_payload_t *certreq_payload_create()
{
	private_certreq_payload_t *this = malloc_thing(private_certreq_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (certreq_payload_t *)) destroy;
	this->public.set_cert_encoding = (void (*) (certreq_payload_t *,cert_encoding_t)) set_cert_encoding;
	this->public.get_cert_encoding = (cert_encoding_t (*) (certreq_payload_t *)) get_cert_encoding;
	this->public.set_data = (void (*) (certreq_payload_t *,chunk_t)) set_data;
	this->public.get_data_clone = (chunk_t (*) (certreq_payload_t *)) get_data_clone;
	this->public.get_data = (chunk_t (*) (certreq_payload_t *)) get_data;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length =CERTREQ_PAYLOAD_HEADER_LENGTH;
	this->certreq_data = CHUNK_INITIALIZER;

	return (&(this->public));
}
