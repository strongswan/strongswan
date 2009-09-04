/*
 * Copyright (C) 2008 Tobias Brunner
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
 */

#include <stddef.h>
#include <ctype.h>

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

	/**
	 * TRUE if the "Hash and URL" data is invalid
	 */
	bool invalid_hash_and_url;
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
	if (this->encoding == ENC_X509_HASH_AND_URL ||
		this->encoding == ENC_X509_HASH_AND_URL_BUNDLE)
	{
		/* coarse verification of "Hash and URL" encoded certificates */
		if (this->data.len <= 20)
		{
			DBG1(DBG_ENC, "invalid payload length for hash-and-url (%d), ignore",
					this->data.len);
			this->invalid_hash_and_url = TRUE;
			return SUCCESS;
		}

		int i = 20; /* skipping the hash */
		for (; i < this->data.len; ++i)
		{
			if (this->data.ptr[i] == '\0')
			{
				/* null terminated, fine */
				return SUCCESS;
			}
			else if (!isprint(this->data.ptr[i]))
			{
				DBG1(DBG_ENC, "non printable characters in url of hash-and-url"
						" encoded certificate payload, ignore");
				this->invalid_hash_and_url = TRUE;
				return SUCCESS;
			}
		}

		/* URL is not null terminated, correct that */
		chunk_t data = chunk_alloc(this->data.len + 1);
		memcpy(data.ptr, this->data.ptr, this->data.len);
		data.ptr[this->data.len] = '\0';
		chunk_free(&this->data);
		this->data = data;
	}
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
 * Implementation of cert_payload_t.get_cert_encoding.
 */
static cert_encoding_t get_cert_encoding(private_cert_payload_t *this)
{
	return this->encoding;
}

/**
 * Implementation of cert_payload_t.get_cert.
 */
static certificate_t *get_cert(private_cert_payload_t *this)
{
	if (this->encoding != ENC_X509_SIGNATURE)
	{
		return NULL;
	}
	return lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_BLOB_ASN1_DER, this->data,
							  BUILD_END);
}

/**
 * Implementation of cert_payload_t.get_hash.
 */
static chunk_t get_hash(private_cert_payload_t *this)
{
	chunk_t hash = chunk_empty;
	if ((this->encoding != ENC_X509_HASH_AND_URL &&
		this->encoding != ENC_X509_HASH_AND_URL_BUNDLE) ||
		this->invalid_hash_and_url)
	{
		return hash;
	}
	hash.ptr = this->data.ptr;
	hash.len = 20;
	return hash;
}

/**
 * Implementation of cert_payload_t.get_url.
 */
static char *get_url(private_cert_payload_t *this)
{
	if ((this->encoding != ENC_X509_HASH_AND_URL &&
		this->encoding != ENC_X509_HASH_AND_URL_BUNDLE) ||
		this->invalid_hash_and_url)
	{
		return NULL;
	}
	return (char*)this->data.ptr + 20;
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
	this->public.get_cert_encoding = (cert_encoding_t (*) (cert_payload_t*))get_cert_encoding;
	this->public.get_hash = (chunk_t (*) (cert_payload_t*))get_hash;
	this->public.get_url = (char* (*) (cert_payload_t*))get_url;

	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = CERT_PAYLOAD_HEADER_LENGTH;
	this->data = chunk_empty;
	this->encoding = 0;
	this->invalid_hash_and_url = FALSE;

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

/*
 * Described in header
 */
cert_payload_t *cert_payload_create_from_hash_and_url(chunk_t hash, char *url)
{
	private_cert_payload_t *this = (private_cert_payload_t*)cert_payload_create();
	chunk_t url_chunk;

	this->encoding = ENC_X509_HASH_AND_URL;

	url_chunk.ptr = url;
	url_chunk.len = strlen(url) + 1;

	this->data = chunk_cat("cc", hash, url_chunk);
	this->payload_length = CERT_PAYLOAD_HEADER_LENGTH + this->data.len;
	return &this->public;
}

