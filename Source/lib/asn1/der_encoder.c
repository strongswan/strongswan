/**
 * @file der_encoder.c
 *
 * @brief Implementation of der_encoder_t.
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

#include <gmp.h>

#include "der_encoder.h"

#include <utils/allocator.h>
#include <daemon.h>



typedef struct private_der_encoder_t private_der_encoder_t;

/**
 * Private data of a der_encoder_t object.
 */
struct private_der_encoder_t {
	/**
	 * Public interface for this signer.
	 */
	der_encoder_t public;
	
	asn1_rule_t *rule;
	
	asn1_rule_t *first_rule;
	
	void *output;
	
	logger_t *logger;
};

static status_t read_hdr(private_der_encoder_t *this, chunk_t *data);

static status_t read_sequence(private_der_encoder_t *this, chunk_t data)
{
	while (this->rule->type != ASN1_END)
	{
		read_hdr(this, &data);
	}
	return SUCCESS;
}


static status_t read_int(private_der_encoder_t *this, chunk_t data)
{
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_INTEGER", data);
	u_int *integ = (u_int*)((u_int8_t*)this->output + this->rule->data_offset);
	
	*integ = 0;
	while (data.len-- > 0)
	{
		*integ = 256 * (*integ) + *data.ptr++;
	}
	return SUCCESS;
}

static status_t read_mpz(private_der_encoder_t *this, chunk_t data)
{
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_INTEGER as mpz", data);
	mpz_t *mpz = (mpz_t*)((u_int8_t*)this->output + this->rule->data_offset);
	
	mpz_import(*mpz, data.len, 1, 1, 1, 0, data.ptr);
	return SUCCESS;
}

static u_int32_t read_length(chunk_t *data)
{
	u_int8_t n;
	size_t len;
	
	/* read first octet of length field */
	n = *data->ptr++;

	if ((n & 0x80) == 0) 
	{
		/* single length octet */
		return n;
	}
	
	/* composite length, determine number of length octets */
	n &= 0x7f;
	
	if (n > data->len)
	{
		/* length longer than available bytes */
		return -1;
	}
	
	if (n > sizeof(len))
	{
		/* larger than size_t can hold */
		return -1;
	}
	
	len = 0;
	while (n-- > 0)
	{
		len = 256 * len + *data->ptr++;
	}
	return len;
}

static status_t read_hdr(private_der_encoder_t *this, chunk_t *data)
{
	chunk_t inner;
	
	/* advance to the next rule */
	this->rule++;
	
	if (this->rule->type == ASN1_END)
	{
		return SUCCESS;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "reading header of rule %s",
					  mapping_find(asn1_type_m, this->rule->type));
	
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "reading from:", *data);
	
	/* read type, advance in data */
	if (*(data->ptr) != this->rule->type)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Bad byte found (%x)", *data->ptr);
		return PARSE_ERROR;
	}
	data->ptr++; 
	data->len--;
	
	/* read length, advance in data */
	inner.len = read_length(data);
	if (inner.len == -1)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Error reading length");
		return PARSE_ERROR;
	}
	this->logger->log(this->logger, CONTROL|LEVEL2, "Length is %d",
					  inner.len);
	inner.ptr = data->ptr;
	
	/* advance in data */
	data->ptr += inner.len;
	data->len -= inner.len;
	
	/* process inner */
	switch (this->rule->type)
	{
		case ASN1_INTEGER:
			if (this->rule->flags & ASN1_MPZ)
			{
				read_mpz(this, inner);
			}
			else
			{
				read_int(this, inner);
			}
			break;
		case ASN1_SEQUENCE:
			read_sequence(this, inner);
			break;
		default:
			break;
	}
	
	return SUCCESS;
}



static status_t decode(private_der_encoder_t *this, chunk_t input, void *output)
{
	this->rule = this->first_rule - 1;
	this->output = output;
	return read_hdr(this, &input);
}

/**
 * Implementation of der_encoder.destroy.
 */
static void destroy(private_der_encoder_t *this)
{
	allocator_free(this);
}

/*
 * Described in header.
 */
der_encoder_t *der_encoder_create(asn1_rule_t *rules)
{
	private_der_encoder_t *this = allocator_alloc_thing(private_der_encoder_t);
	
	/* public functions */
	this->public.decode = (status_t (*) (der_encoder_t*,chunk_t,void*))decode;
	this->public.destroy = (void (*) (der_encoder_t*))destroy;
	
	this->first_rule = rules;
	this->logger = charon->logger_manager->get_logger(charon->logger_manager, DER_DECODER);
	
	return &(this->public);
}
