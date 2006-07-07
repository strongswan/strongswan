/**
 * @file cert_payload.c
 * 
 * @brief Implementation of cert_payload_t.
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

#include "cert_payload.h"


/** 
 * String mappings for cert_encoding_t.
 */
static const char *const cert_encoding_name[] = {
	"CERT_NONE",
	"CERT_PKCS7_WRAPPED_X509",
	"CERT_PGP",
	"CERT_DNS_SIGNED_KEY",
	"CERT_X509_SIGNATURE",
	"CERT_X509_KEY_EXCHANGE",
	"CERT_KERBEROS_TOKENS",
	"CERT_CRL",
	"CERT_ARL",
	"CERT_SPKI",
	"CERT_X509_ATTRIBUTE",
	"CERT_RAW_RSA_KEY",
	"CERT_X509_HASH_AND_URL",
	"CERT_X509_HASH_AND_URL_BUNDLE"
};

enum_names cert_encoding_names =
    { CERT_NONE, CERT_X509_HASH_AND_URL_BUNDLE, cert_encoding_name, NULL };

typedef struct private_cert_payload_t private_cert_payload_t;

/**
 * Private data of an cert_payload_t object.
 * 
 */
struct private_cert_payload_t {
	/**
	 * Public cert_payload_t interface.
	 */
	cert_payload_t public;
	
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
	 * The contained cert data value.
	 */
	chunk_t cert_data;
};

/**
 * Encoding rules to parse or generate a CERT payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_cert_payload_t.
 * 
 */
encoding_rule_t cert_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_cert_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_cert_payload_t, critical) 		},
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	{ RESERVED_BIT,	0 													},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_cert_payload_t, payload_length)},
 	/* 1 Byte CERT type*/
	{ U_INT_8,			offsetof(private_cert_payload_t, cert_encoding)	},
	/* some cert data bytes, length is defined in PAYLOAD_LENGTH */
	{ CERT_DATA,			offsetof(private_cert_payload_t, cert_data) }
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Cert Encoding !                                               !
      +-+-+-+-+-+-+-+-+                                               !
      ~                       Certificate Data                        ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_cert_payload_t *this)
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
 * Implementation of cert_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_cert_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = cert_payload_encodings;
	*rule_count = sizeof(cert_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_payload_type(private_cert_payload_t *this)
{
	return CERTIFICATE;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_cert_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_cert_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_cert_payload_t *this)
{
	return this->payload_length;
}

/**
 * Implementation of cert_payload_t.set_cert_encoding.
 */
static void set_cert_encoding (private_cert_payload_t *this, cert_encoding_t encoding)
{
	this->cert_encoding = encoding;
}

/**
 * Implementation of cert_payload_t.get_cert_encoding.
 */
static cert_encoding_t get_cert_encoding (private_cert_payload_t *this)
{
	return (this->cert_encoding);
}

/**
 * Implementation of cert_payload_t.set_data.
 */
static void set_data (private_cert_payload_t *this, chunk_t data)
{
	if (this->cert_data.ptr != NULL)
	{
		chunk_free(&(this->cert_data));
	}
	this->cert_data.ptr = clalloc(data.ptr,data.len);
	this->cert_data.len = data.len;
	this->payload_length = CERT_PAYLOAD_HEADER_LENGTH + this->cert_data.len;
}

/**
 * Implementation of cert_payload_t.get_data.
 */
static chunk_t get_data (private_cert_payload_t *this)
{
	return (this->cert_data);
}

/**
 * Implementation of cert_payload_t.get_data_clone.
 */
static chunk_t get_data_clone (private_cert_payload_t *this)
{
	chunk_t cloned_data;
	if (this->cert_data.ptr == NULL)
	{
		return (this->cert_data);
	}
	cloned_data.ptr = clalloc(this->cert_data.ptr,this->cert_data.len);
	cloned_data.len = this->cert_data.len;
	return cloned_data;
}

/**
 * Implementation of payload_t.destroy and cert_payload_t.destroy.
 */
static void destroy(private_cert_payload_t *this)
{
	if (this->cert_data.ptr != NULL)
	{
		chunk_free(&(this->cert_data));
	}
	
	free(this);	
}

/*
 * Described in header
 */
cert_payload_t *cert_payload_create()
{
	private_cert_payload_t *this = malloc_thing(private_cert_payload_t);

	/* interface functions */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.destroy = (void (*) (cert_payload_t *)) destroy;
	this->public.set_cert_encoding = (void (*) (cert_payload_t *,cert_encoding_t)) set_cert_encoding;
	this->public.get_cert_encoding = (cert_encoding_t (*) (cert_payload_t *)) get_cert_encoding;
	this->public.set_data = (void (*) (cert_payload_t *,chunk_t)) set_data;
	this->public.get_data_clone = (chunk_t (*) (cert_payload_t *)) get_data_clone;
	this->public.get_data = (chunk_t (*) (cert_payload_t *)) get_data;
	
	/* private variables */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length =CERT_PAYLOAD_HEADER_LENGTH;
	this->cert_data = CHUNK_INITIALIZER;

	return (&(this->public));
}

/*
 * Described in header
 */
cert_payload_t *cert_payload_create_from_x509(x509_t *cert)
{
	cert_payload_t *this = cert_payload_create();

	this->set_cert_encoding(this, CERT_X509_SIGNATURE);
	this->set_data(this, cert->get_certificate(cert));
	return this;
}
