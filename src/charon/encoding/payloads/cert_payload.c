/*
 * Copyright (C) 2005-2007 Martin Willi
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
 *
 * $Id$
 */

#include <stddef.h>

#include <daemon.h>

#include "cert_payload.h"

ENUM(cert_encoding_names, ENC_PKCS7_WRAPPED_X509, ENC_OCSP_CONTENT,
	"ENC_PKCS7_WRAPPED_X509",
	"ENC_PGP",
	"ENC_DNS_SIGNED_KEY",
	"ENC_X509_SIGNATURE",
	"ENC_X509_KEY_EXCHANGE",
	"ENC_KERBEROS_TOKENS",
	"ENC_CRL",
	"ENC_ARL",
	"ENC_SPKI",
	"ENC_X509_ATTRIBUTE",
	"ENC_RAW_RSA_KEY",
	"ENC_X509_HASH_AND_URL",
	"ENC_X509_HASH_AND_URL_BUNDLE",
	"ENC_OCSP_CONTENT",
);

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
	u_int8_t encoding;
	
	/**
	 * The contained cert data value.
	 */
	chunk_t data;
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
	{ U_INT_8,			offsetof(private_cert_payload_t, encoding)		},
	/* some cert data bytes, length is defined in PAYLOAD_LENGTH */
	{ CERT_DATA,		offsetof(private_cert_payload_t, data) 			}
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
	return SUCCESS;
}

/**
 * Implementation of cert_payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_cert_payload_t *this,
							   encoding_rule_t **rules, size_t *rule_count)
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
	return this->next_payload;
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
 * Implementation of cert_payload_t.get_cert.
 */
static certificate_t* get_cert(private_cert_payload_t *this)
{
	certificate_type_t type;
	
	switch (this->encoding)
	{
		case ENC_X509_SIGNATURE:
			type = CERT_X509;
			break;
		case ENC_PKCS7_WRAPPED_X509:
		case ENC_PGP:
		case ENC_DNS_SIGNED_KEY:
		case ENC_KERBEROS_TOKEN:
		case ENC_CRL:
		case ENC_ARL:
		case ENC_SPKI:
		case ENC_X509_ATTRIBUTE:
		case ENC_RAW_RSA_KEY:
		case ENC_X509_HASH_AND_URL:
		case ENC_X509_HASH_AND_URL_BUNDLE:
		case ENC_OCSP_CONTENT:
		default:
			DBG1(DBG_ENC, "certificate encoding %N not supported",
				 cert_encoding_names, this->encoding);
			return NULL;
	}
	return lib->creds->create(lib->creds, CRED_CERTIFICATE, type,
							  BUILD_BLOB_ASN1_DER, chunk_clone(this->data),
							  BUILD_END);
}

/**
 * Implementation of payload_t.destroy and cert_payload_t.destroy.
 */
static void destroy(private_cert_payload_t *this)
{
	chunk_free(&this->data);
	free(this);	
}

/*
 * Described in header
 */
cert_payload_t *cert_payload_create()
{
	private_cert_payload_t *this = malloc_thing(private_cert_payload_t);

	this->public.payload_interface.verify = (status_t (*) (payload_t*))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t*,encoding_rule_t**, size_t*))get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t*))get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t*))get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t*,payload_type_t))set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t*))get_payload_type;
	this->public.payload_interface.destroy = (void (*) (payload_t*))destroy;
	
	this->public.destroy = (void (*) (cert_payload_t*))destroy;
	this->public.get_cert = (certificate_t* (*) (cert_payload_t*))get_cert;
	
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = CERT_PAYLOAD_HEADER_LENGTH;
	this->data = chunk_empty;
	this->encoding = 0;

	return &this->public;
}

/*
 * Described in header
 */
cert_payload_t *cert_payload_create_from_cert(certificate_t *cert)
{
	private_cert_payload_t *this = (private_cert_payload_t*)cert_payload_create();

	switch (cert->get_type(cert))
	{
		case CERT_X509:
			this->encoding = ENC_X509_SIGNATURE;
			break;
		default:
			DBG1(DBG_ENC, "embedding %N certificate in payload failed",
				 certificate_type_names, cert->get_type(cert));
			free(this);
			return NULL;
	}
	this->data = cert->get_encoding(cert);
	this->payload_length = CERT_PAYLOAD_HEADER_LENGTH + this->data.len;
	return &this->public;
}

