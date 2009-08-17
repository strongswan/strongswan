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

#include "dnskey_builder.h"

#include <debug.h>
#include <credentials/keys/private_key.h>


typedef struct dnskey_rr_t dnskey_rr_t;
typedef enum dnskey_algorithm_t dnskey_algorithm_t;

/**
 * Header of a DNSKEY resource record
 */
struct dnskey_rr_t {
	u_int16_t flags;
	u_int8_t protocol;
	u_int8_t algorithm;
	u_int8_t data[];
} __attribute__((__packed__));

/**
 * DNSSEC algorithms, RFC4034 Appendix A.1.
 */
enum dnskey_algorithm_t {
	DNSKEY_ALG_RSA_MD5 = 1,
	DNSKEY_ALG_DH = 2,
	DNSKEY_ALG_DSA = 3,
	DNSKEY_ALG_ECC = 4,
	DNSKEY_ALG_RSA_SHA1 = 5,
};

/**
 * Load a generic public key from a DNSKEY RR blob
 */
static public_key_t *parse_public_key(chunk_t blob)
{
	dnskey_rr_t *rr = (dnskey_rr_t*)blob.ptr;
	
	if (blob.len < sizeof(dnskey_rr_t))
	{
		DBG1("DNSKEY too short");
		return NULL;
	}
	blob = chunk_skip(blob, sizeof(dnskey_rr_t));
	
	switch (rr->algorithm)
	{
		case DNSKEY_ALG_RSA_SHA1:
			return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
									  BUILD_BLOB_DNSKEY, blob, BUILD_END);
		default:
			DBG1("DNSKEY public key algorithm %d not supported", rr->algorithm);
			return NULL;
	}
}

/**
 * Load a RSA public key from DNSKEY RR data
 */
static public_key_t *parse_rsa_public_key(chunk_t blob)
{
	chunk_t n, e;
	
	if (blob.len < 3)
	{
		DBG1("RFC 3110 public key blob too short for exponent length");
		return NULL;
	}
	
	if (blob.ptr[0])
	{
		e.len = blob.ptr[0];
		blob = chunk_skip(blob, 1);
	}
	else
	{
		e.len = blob.ptr[1] * 256 + blob.ptr[2];
		blob = chunk_skip(blob, 3);
	}
	e.ptr = blob.ptr;
	if (e.len >= blob.len)
	{
		DBG1("RFC 3110 public key blob too short for exponent");
		return NULL;
	}
	n = chunk_skip(blob, e.len);
	
	return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
						BUILD_RSA_MODULUS, n, BUILD_RSA_PUB_EXP, e,
						BUILD_END);
}

typedef struct private_builder_t private_builder_t;

/**
 * Builder implementation for private/public key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** dnskey packet data */
	chunk_t blob;
	/** type of key to build */
	key_type_t type;
};

/**
 * Implementation of builder_t.build for public keys
 */
static public_key_t *build_public(private_builder_t *this)
{
	public_key_t *key = NULL;
	
	switch (this->type)
	{
		case KEY_ANY:
			key = parse_public_key(this->blob);
			break;
		case KEY_RSA:
			key = parse_rsa_public_key(this->blob);
			break;
		default:
			break;
	}
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add for public keys
 */
static void add_public(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	switch (part)
	{
		case BUILD_BLOB_DNSKEY:
		{
			va_start(args, part);
			this->blob = va_arg(args, chunk_t);
			va_end(args);
			break;
		}
		default:
			builder_cancel(&this->public);
			break;
	}
}

/**
 * Builder construction function for public keys
 */
builder_t *dnskey_public_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_ANY && type != KEY_RSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->blob = chunk_empty;
	this->type = type;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add_public;
	this->public.build = (void*(*)(builder_t *this))build_public;
	
	return &this->public;
}

