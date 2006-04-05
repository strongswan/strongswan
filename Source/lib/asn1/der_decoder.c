/**
 * @file der_decoder.c
 *
 * @brief Implementation of der_decoder_t.
 */

/*
 * Copyright (C) 2000-2004 Andreas Steffen
 * Copyright (C) 2006 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * Some parts taken over from pluto/asn1.c
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

#include "der_decoder.h"

#include <utils/allocator.h>
#include <daemon.h>



typedef struct private_der_decoder_t private_der_decoder_t;

/**
 * Private data of a der_decoder_t object.
 */
struct private_der_decoder_t {
	/**
	 * Public interface for this signer.
	 */
	der_decoder_t public;
	
	/**
	 * Rule which was just processed
	 */
	asn1_rule_t *rule;
	
	/**
	 * First rule of the whole ruleset
	 */
	asn1_rule_t *first_rule;
	
	/**
	 * Output data struct
	 */
	void *output;
	
	/**
	 * Complex things like this need a logger ;-)
	 */
	logger_t *logger;
};

status_t read_hdr(private_der_decoder_t *this, chunk_t *data);

/**
 * Read a sequence from data, parse its contents recursivly
 */
status_t read_sequence(private_der_decoder_t *this, chunk_t data)
{
	status_t status;
	asn1_rule_t *next_rule;
	
	while(TRUE)
	{
		next_rule = this->rule + 1;
		if (next_rule->type == ASN1_END)
		{
			this->rule++;
			break;
		}
		status = read_hdr(this, &data);
		if (status != SUCCESS)
		{
			return status;
		}
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Sequence end");
	return SUCCESS;
}

/**
 * Read choice of data, parse if one of the choosable types arise
 */
status_t read_choice(private_der_decoder_t *this, chunk_t *data)
{
	status_t status = PARSE_ERROR;
	asn1_rule_t *next_rule;
	bool found = FALSE;
	
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "Choice data", *data);
	
	while(TRUE)
	{
		next_rule = this->rule + 1;
		if (next_rule->type == ASN1_END)
		{
			this->rule++;
			return status;
		}
		if (!found && *(data->ptr) == next_rule->type)
		{
			found = TRUE;
			status = read_hdr(this, data);
		}
		else
		{
			this->rule++;
		}
	}
	this->logger->log(this->logger, CONTROL|LEVEL2, "Choice end");
	return status;
}

/**
 * Read a utc or generalized time
 */
status_t read_time(private_der_decoder_t *this, chunk_t data)
{
	struct tm t;
	time_t tz_offset;
	u_char *eot = NULL;
	const char* format;
	time_t *result = (time_t*)((u_int8_t*)this->output + this->rule->data_offset);
	
	/* TODO: Test it */
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "TIME", data);
	
	if ((eot = memchr(data.ptr, 'Z', data.len)) != NULL)
	{
		/* Zulu time with a zero time zone offset */
		tz_offset = 0;
	}
	else if ((eot = memchr(data.ptr, '+', data.len)) != NULL)
	{
		int tz_hour, tz_min;
		
		sscanf(eot+1, "%2d%2d", &tz_hour, &tz_min);
		/* positive time zone offset */
		tz_offset = 3600*tz_hour + 60*tz_min;
	}
	else if ((eot = memchr(data.ptr, '-', data.len)) != NULL)
	{
		int tz_hour, tz_min;
		
		sscanf(eot+1, "%2d%2d", &tz_hour, &tz_min);
		/* negative time zone offset */
		tz_offset = -3600*tz_hour - 60*tz_min;
	}
	else
	{
		/* error in time format */
		return PARSE_ERROR; 
	}

	if (this->rule->type == ASN1_UTCTIME)
	{
		format = "%2d%2d%2d%2d%2d";
	}
	else
	{
		format = "%4d%2d%2d%2d%2d";
	}
	
	sscanf(data.ptr, format, &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min);
	
	/* is there a seconds field? */
	if ((eot - data.ptr) == ((this->rule->type == ASN1_UTCTIME)?12:14))
	{
		sscanf(eot-2, "%2d", &t.tm_sec);
	}
	else
	{
		t.tm_sec = 0;
	}

	/* representation of year */
	if (t.tm_year >= 1900)
	{
		t.tm_year -= 1900;
	}
	else if (t.tm_year >= 100)
	{
		return PARSE_ERROR;
	}
	else if (t.tm_year < 50)
	{
		t.tm_year += 100;
	}

	/* representation of month 0..11*/
	t.tm_mon--;

	/* set daylight saving time to off */
	t.tm_isdst = 0;

	/* compensate timezone */

	*result = mktime(&t) - timezone - tz_offset;
	return SUCCESS;
}

/**
 * Read an integer as u_int or as mpz_t
 */
status_t read_int(private_der_decoder_t *this, chunk_t data)
{
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_INTEGER", data);
	
	if (this->rule->flags & ASN1_MPZ)
	{
		mpz_t *mpz = (mpz_t*)((u_int8_t*)this->output + this->rule->data_offset);
		mpz_import(*mpz, data.len, 1, 1, 1, 0, data.ptr);
	}
	else
	{	
		u_int *integ = (u_int*)((u_int8_t*)this->output + this->rule->data_offset);
		
		*integ = 0;
		while (data.len-- > 0)
		{
			*integ = 256 * (*integ) + *data.ptr++;
		}
	}
	return SUCCESS;
}

/**
 * Read boolean value 
 */
status_t read_bool(private_der_decoder_t *this, chunk_t data)
{
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_BOOLEAN", data);

	bool *boolean = (u_int*)((u_int8_t*)this->output + this->rule->data_offset);
	
	*boolean = *data.ptr;
	
	return SUCCESS;
}

/**
 * Read an OID
 */
status_t read_oid(private_der_decoder_t *this, chunk_t data)
{
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_OID", data);
	/* TODO: OID parsing stuff */
	return SUCCESS;
}

/**
 * Read a bitstring
 */
status_t read_bitstring(private_der_decoder_t *this, chunk_t data)
{
	/* TODO: cleanly determine amount of unused bits */
	
	/* skip "unused-bits-in-following-byte"-byte */
	data.ptr += 1;
	data.len -= 1;
	
	if (data.len < 1)
	{
		return FAILED;
	}
	
	chunk_t *chunk = (chunk_t*)((u_int8_t*)this->output + this->rule->data_offset);
	
	*chunk = allocator_clone_chunk(data);
	
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_BITSTRING", data);
	return SUCCESS;
}

/**
 * Read any type which appears in a chunk
 */
status_t read_any(private_der_decoder_t *this, chunk_t data)
{	
	chunk_t *chunk = (chunk_t*)((u_int8_t*)this->output + this->rule->data_offset);
	
	*chunk = allocator_clone_chunk(data);
	
	this->logger->log_chunk(this->logger, CONTROL|LEVEL2, "ASN1_ANY", data);
	return SUCCESS;
}

/**
 * Read the length field of a type
 */
u_int32_t read_length(chunk_t *data)
{
	u_int8_t n;
	size_t len;
	
	if (data->len < 1)
	{
		return -1;
	}
	
	/* read first octet of length field */
	n = *data->ptr;
	data->ptr++; data->len--;

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
		len = 256 * len + *data->ptr;
		data->ptr++; data->len--;
	}
	return len;
}

/**
 * Read the next field
 */
status_t read_hdr(private_der_decoder_t *this, chunk_t *data)
{
	chunk_t inner;
	/* TODO: Redo this that an average mid-european can understand it */
	
beginning:
	/* advance to the next rule */
	this->rule++;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "reading rule %d %s",
						this->rule - this->first_rule,
						mapping_find(asn1_type_m, this->rule->type));
	
	switch (this->rule->type)
	{
		case ASN1_END:
			/* ignore, handled outside */
			return SUCCESS;
		case ASN1_CHOICE:
			/* CHOICE has no type/length */
			break;
		default:
			/* anything else has type/length */
			if (data->len == 0)
			{
				goto beginning;
			}
			this->logger->log_chunk(this->logger, CONTROL|LEVEL3, "reading from:", *data);
			
			/* read type, advance in data */
			if (this->rule->type != ASN1_ANY && *(data->ptr) != this->rule->type)
			{
				if (this->rule->flags & ASN1_OPTIONAL)
				{
					goto beginning;
				}
				if (this->rule->flags & ASN1_DEFAULT)
				{
					goto beginning;
				}
				this->logger->log(this->logger, CONTROL|LEVEL2, "Bad byte found: %x, %x expected", 
								*data->ptr, this->rule->type);
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
			this->logger->log(this->logger, CONTROL|LEVEL2, "Length is %d", inner.len);
			inner.ptr = data->ptr;
			
			/* advance in data, at the size of the inner */
			data->ptr += inner.len;
			data->len -= inner.len;
	}
	
	/* process inner */
	while (TRUE)
	{
		switch (this->rule->type)
		{
			case ASN1_INTEGER:
				return read_int(this, inner);
			case ASN1_BOOLEAN:
				return read_bool(this, inner);
			case ASN1_SEQUENCE:
			case ASN1_SET:
				return read_sequence(this, inner);
			case ASN1_TAG_E_0:
			case ASN1_TAG_E_1:
			case ASN1_TAG_E_2:
			case ASN1_TAG_E_3:
			case ASN1_TAG_E_4:
			case ASN1_TAG_E_5:
			case ASN1_TAG_E_6:
			case ASN1_TAG_E_7:
				return read_hdr(this, &inner);
			case ASN1_TAG_I_0:
			case ASN1_TAG_I_1:
			case ASN1_TAG_I_2:
			case ASN1_TAG_I_3:
			case ASN1_TAG_I_4:
			case ASN1_TAG_I_5:
			case ASN1_TAG_I_6:
			case ASN1_TAG_I_7:
				this->rule++;
				continue;
			case ASN1_OID:
				return read_oid(this, inner);
			case ASN1_CHOICE:
				return read_choice(this, data);
			case ASN1_NULL:
				return SUCCESS;
			case ASN1_ANY:
				return read_any(this, inner);
			case ASN1_UTCTIME:
				return read_time(this, inner);
			case  ASN1_GENERALIZEDTIME:
				return read_time(this, inner);
			case ASN1_BITSTRING:
				return read_bitstring(this, inner);
			case ASN1_OCTETSTRING:
				return read_any(this, inner);
			default:
				return NOT_SUPPORTED;
		}
	}
}

/**
 * Implements der_decoder_t.decode
 */
status_t decode(private_der_decoder_t *this, chunk_t input, void *output)
{
	this->rule = this->first_rule - 1;
	this->output = output;
	/* start parsing recursivly */
	return read_hdr(this, &input);
}

/**
 * Implementation of der_decoder.destroy.
 */
static void destroy(private_der_decoder_t *this)
{
	this->logger->destroy(this->logger);
	allocator_free(this);
}

/*
 * Described in header.
 */
der_decoder_t *der_decoder_create(asn1_rule_t *rules)
{
	private_der_decoder_t *this = allocator_alloc_thing(private_der_decoder_t);
	
	/* public functions */
	this->public.decode = (status_t (*) (der_decoder_t*,chunk_t,void*))decode;
	this->public.destroy = (void (*) (der_decoder_t*))destroy;
	
	this->first_rule = rules;
	this->logger = logger_create("[DERDC]", CONTROL, FALSE, NULL);
	
	return &(this->public);
}
