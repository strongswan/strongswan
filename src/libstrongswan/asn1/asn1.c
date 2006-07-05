/* Simple ASN.1 parser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2006 Martin Will, Hochschule fuer Technik Rapperswil
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "types.h"
#include "asn1.h"

#include <utils/logger_manager.h>

/* some common prefabricated ASN.1 constants */
static u_char ASN1_INTEGER_0_str[] = { 0x02, 0x00 };
static u_char ASN1_INTEGER_1_str[] = { 0x02, 0x01, 0x01 };
static u_char ASN1_INTEGER_2_str[] = { 0x02, 0x01, 0x02 };

const chunk_t ASN1_INTEGER_0 = chunk_from_buf(ASN1_INTEGER_0_str);
const chunk_t ASN1_INTEGER_1 = chunk_from_buf(ASN1_INTEGER_1_str);
const chunk_t ASN1_INTEGER_2 = chunk_from_buf(ASN1_INTEGER_2_str);

/* some popular algorithmIdentifiers */

static u_char ASN1_md5_id_str[] = {
	0x30, 0x0C,
	0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05,
	0x05, 0x00
};

static u_char ASN1_sha1_id_str[] = {
	0x30, 0x09,
	0x06, 0x05, 0x2B, 0x0E,0x03, 0x02, 0x1A,
	0x05, 0x00
};

static u_char ASN1_md5WithRSA_id_str[] = {
	0x30, 0x0D,
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04,
	0x05, 0x00
};

static u_char ASN1_sha1WithRSA_id_str[] = {
	0x30, 0x0D,
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
	0x05, 0x00
};

static u_char ASN1_rsaEncryption_id_str[] = {
	0x30, 0x0D,
	0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
	0x05, 0x00
};

const chunk_t ASN1_md5_id = chunk_from_buf(ASN1_md5_id_str);
const chunk_t ASN1_sha1_id = chunk_from_buf(ASN1_sha1_id_str);
const chunk_t ASN1_rsaEncryption_id = chunk_from_buf(ASN1_rsaEncryption_id_str);
const chunk_t ASN1_md5WithRSA_id = chunk_from_buf(ASN1_md5WithRSA_id_str);
const chunk_t ASN1_sha1WithRSA_id = chunk_from_buf(ASN1_sha1WithRSA_id_str);

/* ASN.1 definiton of an algorithmIdentifier */
static const asn1Object_t algorithmIdentifierObjects[] = {
	{ 0, "algorithmIdentifier",	ASN1_SEQUENCE,	ASN1_NONE }, /* 0 */
	{ 1,   "algorithm",			ASN1_OID,		ASN1_BODY }, /* 1 */
	{ 1,   "parameters",		ASN1_EOC,		ASN1_RAW  }  /* 2 */
};

#define ALGORITHM_ID_ALG		1
#define ALGORITHM_ID_PARAMETERS	2
#define ALGORITHM_ID_ROOF		3

static logger_t *logger = NULL;

/**
 * initializes the ASN.1 logger
 */
static void asn1_init_logger(void)
{
	if (logger == NULL)
		logger = logger_manager->get_logger(logger_manager, ASN1);
}

/**
 * return the ASN.1 encoded algorithm identifier
 */
chunk_t asn1_algorithmIdentifier(int oid)
{
	switch (oid)
	{
		case OID_RSA_ENCRYPTION:
			return ASN1_rsaEncryption_id;
		case OID_MD5_WITH_RSA:
			return ASN1_md5WithRSA_id;
		case OID_SHA1_WITH_RSA:
			return ASN1_sha1WithRSA_id;
		case OID_MD5:
			return ASN1_md5_id;
		case OID_SHA1:
			return ASN1_sha1_id;
		default:
			return CHUNK_INITIALIZER;
	}
}

/**
 * If the oid is listed in the oid_names table then the corresponding
 * position in the oid_names table is returned otherwise -1 is returned
 */
int known_oid(chunk_t object)
{
	int oid = 0;
	
	while (object.len)
	{
		if (oid_names[oid].octet == *object.ptr)
		{
			if (--object.len == 0 || oid_names[oid].down == 0)
			{
				return oid;          /* found terminal symbol */
			}
			else
			{
				object.ptr++; oid++; /* advance to next hex octet */
			}
		}
		else
		{
			if (oid_names[oid].next)
				oid = oid_names[oid].next;
			else
				return OID_UNKNOWN;
		}
	}
	return -1;
}

/**
 * Decodes the length in bytes of an ASN.1 object
 */
u_int asn1_length(chunk_t *blob)
{
	u_char n;
	size_t len;
	
	/* advance from tag field on to length field */
	blob->ptr++;
	blob->len--;
	
	/* read first octet of length field */
	n = *blob->ptr++;
	blob->len--;
	
	if ((n & 0x80) == 0) 
	{/* single length octet */
		return n;
	}
	
	/* composite length, determine number of length octets */
	n &= 0x7f;
	
	if (n > blob->len)
	{
		logger->log(logger, ERROR|LEVEL1, "number of length octets is larger than ASN.1 object");
		return ASN1_INVALID_LENGTH;
	}
	
	if (n > sizeof(len))
	{
		logger->log(logger, ERROR|LEVEL1, "number of length octets is larger than limit of %d octets", 
					(int)sizeof(len));
		return ASN1_INVALID_LENGTH;
	}
	
	len = 0;
	
	while (n-- > 0)
	{
		len = 256*len + *blob->ptr++;
		blob->len--;
	}
	return len;
}

/**
 * determines if a character string is of type ASN.1 printableString
 */
bool is_printablestring(chunk_t str)
{
	const char printablestring_charset[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
	u_int i;
	
	for (i = 0; i < str.len; i++)
	{
		if (strchr(printablestring_charset, str.ptr[i]) == NULL)
			return FALSE;
	}
	return TRUE;
}

/**
 * Converts ASN.1 UTCTIME or GENERALIZEDTIME into calender time
 */
time_t asn1totime(const chunk_t *utctime, asn1_t type)
{
	struct tm t;
	time_t tz_offset;
	u_char *eot = NULL;
	
	if ((eot = memchr(utctime->ptr, 'Z', utctime->len)) != NULL)
	{
		tz_offset = 0; /* Zulu time with a zero time zone offset */
	}
	else if ((eot = memchr(utctime->ptr, '+', utctime->len)) != NULL)
	{
		int tz_hour, tz_min;
	
		sscanf(eot+1, "%2d%2d", &tz_hour, &tz_min);
		tz_offset = 3600*tz_hour + 60*tz_min;  /* positive time zone offset */
	}
	else if ((eot = memchr(utctime->ptr, '-', utctime->len)) != NULL)
	{
		int tz_hour, tz_min;
	
		sscanf(eot+1, "%2d%2d", &tz_hour, &tz_min);
		tz_offset = -3600*tz_hour - 60*tz_min;  /* negative time zone offset */
	}
	else
	{
		return 0; /* error in time format */
	}
	
	{
	const char* format = (type == ASN1_UTCTIME)? "%2d%2d%2d%2d%2d":
			"%4d%2d%2d%2d%2d";
	
	sscanf(utctime->ptr, format, &t.tm_year, &t.tm_mon, &t.tm_mday,
		   &t.tm_hour, &t.tm_min);
	}
	
	/* is there a seconds field? */
	if ((eot - utctime->ptr) == ((type == ASN1_UTCTIME)?12:14))
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
		return 0;
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
	
	return mktime(&t) - timezone - tz_offset;
}

/**
 * Initializes the internal context of the ASN.1 parser
 */
void asn1_init(asn1_ctx_t *ctx, chunk_t blob, u_int level0, bool implicit)
{
	asn1_init_logger();

	ctx->blobs[0] = blob;
	ctx->level0   = level0;
	ctx->implicit = implicit;
	memset(ctx->loopAddr, '\0', sizeof(ctx->loopAddr));
}

/**
 * print the value of an ASN.1 simple object
 */
static void debug_asn1_simple_object(chunk_t object, asn1_t type)
{
	int oid;
	
	switch (type)
	{
		case ASN1_OID:
			oid = known_oid(object);
			if (oid != OID_UNKNOWN)
			{
				logger->log(logger, CONTROL|LEVEL2, "  '%s'", oid_names[oid].name);
				return;
			}
			break;
		case ASN1_UTF8STRING:
		case ASN1_IA5STRING:
		case ASN1_PRINTABLESTRING:
		case ASN1_T61STRING:
		case ASN1_VISIBLESTRING:
			logger->log(logger, CONTROL|LEVEL2, "  '%.*s'", (int)object.len, object.ptr);
			return;
		case ASN1_UTCTIME:
		case ASN1_GENERALIZEDTIME:
			{
				char buf[TIMETOA_BUF];
				time_t time = asn1totime(&object, type);

				timetoa(buf, TIMETOA_BUF, &time, TRUE);
				logger->log(logger, CONTROL|LEVEL2, "  '%s'", buf);
			}
			return;
		default:
			break;
	}
	logger->log_chunk(logger, RAW|LEVEL1, "", object);
}

/**
 * Parses and extracts the next ASN.1 object
 */
bool extract_object(asn1Object_t const *objects, u_int *objectID, chunk_t *object, u_int *level, asn1_ctx_t *ctx)
{
	asn1Object_t obj = objects[*objectID];
	chunk_t *blob;
	chunk_t *blob1;
	u_char *start_ptr;
	
	*object = CHUNK_INITIALIZER;
	
	if (obj.flags & ASN1_END)  /* end of loop or option found */
	{
		if (ctx->loopAddr[obj.level] && ctx->blobs[obj.level+1].len > 0)
		{
			*objectID = ctx->loopAddr[obj.level]; /* another iteration */
			obj = objects[*objectID];
		}
		else
		{
			ctx->loopAddr[obj.level] = 0;         /* exit loop or option*/
			return TRUE;
		}
	}
	
	*level = ctx->level0 + obj.level;
	blob = ctx->blobs + obj.level;
	blob1 = blob + 1;
	start_ptr = blob->ptr;
	
	/* handle ASN.1 defaults values */
	if ((obj.flags & ASN1_DEF) && (blob->len == 0 || *start_ptr != obj.type) )
	{
		/* field is missing */
		logger->log(logger, CONTROL|LEVEL2, "L%d - %s:", *level, obj.name);
		if (obj.type & ASN1_CONSTRUCTED)
		{
			(*objectID)++ ;  /* skip context-specific tag */
		}
		return TRUE;
	}
	
	/* handle ASN.1 options */
	
	if ((obj.flags & ASN1_OPT)
			&& (blob->len == 0 || *start_ptr != obj.type))
	{
		/* advance to end of missing option field */
		do
			(*objectID)++;
		while (!((objects[*objectID].flags & ASN1_END)
						&& (objects[*objectID].level == obj.level)));
		return TRUE;
	}
		
	/* an ASN.1 object must possess at least a tag and length field */
	
	if (blob->len < 2)
	{
		logger->log(logger, ERROR|LEVEL1, "L%d - %s:  ASN.1 object smaller than 2 octets", 
					*level, obj.name);
		return FALSE;
	}
	
	blob1->len = asn1_length(blob);
	
	if (blob1->len == ASN1_INVALID_LENGTH || blob->len < blob1->len)
	{
		logger->log(logger, ERROR|LEVEL1, "L%d - %s:  length of ASN.1 object invalid or too large", 
					*level, obj.name);
		return FALSE;
	}
	
	blob1->ptr = blob->ptr;
	blob->ptr += blob1->len;
	blob->len -= blob1->len;
	
	/* return raw ASN.1 object without prior type checking */
	
	if (obj.flags & ASN1_RAW)
	{
		logger->log(logger, CONTROL|LEVEL2, "L%d - %s:", *level, obj.name);
		object->ptr = start_ptr;
		object->len = (size_t)(blob->ptr - start_ptr);
		return TRUE;
	}

	if (*start_ptr != obj.type && !(ctx->implicit && *objectID == 0))
	{
		logger->log(logger, ERROR|LEVEL1, "L%d - %s: ASN1 tag 0x%02x expected, but is 0x%02x",
					*level, obj.name, obj.type, *start_ptr);
		logger->log_bytes(logger, RAW|LEVEL1, "", start_ptr, (u_int)(blob->ptr - start_ptr));
		return FALSE;
	}
	
	logger->log(logger, CONTROL|LEVEL2, "L%d - %s:", ctx->level0+obj.level, obj.name);
	
	/* In case of "SEQUENCE OF" or "SET OF" start a loop */	
	if (obj.flags & ASN1_LOOP)
	{
		if (blob1->len > 0)
		{
			/* at least one item, start the loop */
			ctx->loopAddr[obj.level] = *objectID + 1;
		}
		else
		{
			/* no items, advance directly to end of loop */
			do
				(*objectID)++;
			while (!((objects[*objectID].flags & ASN1_END)
							   && (objects[*objectID].level == obj.level)));
			return TRUE;
		}
	}

	if (obj.flags & ASN1_OBJ)
	{
		object->ptr = start_ptr;
		object->len = (size_t)(blob->ptr - start_ptr);
		logger->log_chunk(logger, RAW|LEVEL2, "", *object);
	}
	else if (obj.flags & ASN1_BODY)
	{
		*object = *blob1;
		debug_asn1_simple_object(*object, obj.type);
	}
	return TRUE;
}

/**
 * parse an ASN.1 simple type
 */
bool parse_asn1_simple_object(chunk_t *object, asn1_t type, u_int level, const char* name)
{
	size_t len;
	
	/* an ASN.1 object must possess at least a tag and length field */
	if (object->len < 2)
	{
		logger->log(logger, ERROR|LEVEL1, "L%d - %s:  ASN.1 object smaller than 2 octets", 
					level, name);
		return FALSE;
	}
	
	if (*object->ptr != type)
	{
		logger->log(logger, ERROR|LEVEL1, "L%d - %s: ASN1 tag 0x%02x expected, but is 0x%02x",
					level, name, type, *object->ptr);
		return FALSE;
	}
	
	len = asn1_length(object);
	
	if (len == ASN1_INVALID_LENGTH || object->len < len)
	{
		logger->log(logger, ERROR|LEVEL1, "L%d - %s:  length of ASN.1 object invalid or too large",
					level, name);
		return FALSE;
	}
	
	logger->log(logger, CONTROL|LEVEL2, "L%d - %s:", level, name);
	debug_asn1_simple_object(*object, type);
	return TRUE;
}

/**
 * extracts an algorithmIdentifier
 */
int parse_algorithmIdentifier(chunk_t blob, int level0, chunk_t *parameters)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int alg = OID_UNKNOWN;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, FALSE);
	
	while (objectID < ALGORITHM_ID_ROOF)
	{
		if (!extract_object(algorithmIdentifierObjects, &objectID, &object, &level, &ctx))
			return OID_UNKNOWN;
		
		switch (objectID)
		{
			case ALGORITHM_ID_ALG:
				alg = known_oid(object);
				break;
			case ALGORITHM_ID_PARAMETERS:
				if (parameters != NULL)
					*parameters = object;
				break;
			default:
				break;
		}
		objectID++;
	}
	return alg;
 }

/*
 *  tests if a blob contains a valid ASN.1 set or sequence
 */
bool is_asn1(chunk_t blob)
{
	u_int len;
	u_char tag = *blob.ptr;
	
	asn1_init_logger();

	if (tag != ASN1_SEQUENCE && tag != ASN1_SET)
	{
		logger->log(logger, ERROR|LEVEL2, "  file content is not binary ASN.1");
		return FALSE;
	}
	len = asn1_length(&blob);
	if (len != blob.len)
	{
		logger->log(logger, ERROR|LEVEL2, "  file size does not match ASN.1 coded length");
		return FALSE;
	}
	return TRUE;
}

/**
 * codes ASN.1 lengths up to a size of 16'777'215 bytes
 */
void code_asn1_length(size_t length, chunk_t *code)
{
	if (length < 128)
	{
		code->ptr[0] = length;
		code->len = 1;
	}
	else if (length < 256)
	{
		code->ptr[0] = 0x81;
		code->ptr[1] = (u_char) length;
		code->len = 2;
	}
	else if (length < 65536)
	{
		code->ptr[0] = 0x82;
		code->ptr[1] = length >> 8;
		code->ptr[2] = length & 0x00ff;
		code->len = 3;
	}
	else
	{
		code->ptr[0] = 0x83;
		code->ptr[1] = length >> 16;
		code->ptr[2] = (length >> 8) & 0x00ff;
		code->ptr[3] = length & 0x0000ff;
		code->len = 4;
	}
}

/**
 * build an empty asn.1 object with tag and length fields already filled in
 */
u_char* build_asn1_object(chunk_t *object, asn1_t type, size_t datalen)
{
	u_char length_buf[4];
	chunk_t length = { length_buf, 0 };
	u_char *pos;
	
	/* code the asn.1 length field */
	code_asn1_length(datalen, &length);
	
	/* allocate memory for the asn.1 TLV object */
	object->len = 1 + length.len + datalen;
	object->ptr = malloc(object->len);
	
	/* set position pointer at the start of the object */
	pos = object->ptr;
	
	/* copy the asn.1 tag field and advance the pointer */
	*pos++ = type;
	
	/* copy the asn.1 length field and advance the pointer */
	memcpy(pos, length.ptr, length.len); 
	pos += length.len;
	
	return pos;
}

/**
 * build a simple ASN.1 object
 */
chunk_t asn1_simple_object(asn1_t tag, chunk_t content)
{
	chunk_t object;
	
	u_char *pos = build_asn1_object(&object, tag, content.len);
	memcpy(pos, content.ptr, content.len); 
	pos += content.len;
	
	return object;
}

/**
 * Build an ASN.1 object from a variable number of individual chunks.
 * Depending on the mode, chunks either are moved ('m') or copied ('c').
 */
chunk_t asn1_wrap(asn1_t type, const char *mode, ...)
{
	chunk_t construct;
	va_list chunks;
	u_char *pos;
	int i;
	int count = strlen(mode);
	
	/* sum up lengths of individual chunks */ 
	va_start(chunks, mode);
	construct.len = 0;
	for (i = 0; i < count; i++)
	{
		chunk_t ch = va_arg(chunks, chunk_t);
		construct.len += ch.len;
	}
	va_end(chunks);
	
	/* allocate needed memory for construct */
	pos = build_asn1_object(&construct, type, construct.len);
	
	/* copy or move the chunks */
	va_start(chunks, mode);
	for (i = 0; i < count; i++)
	{
		chunk_t ch = va_arg(chunks, chunk_t);
		
		switch (*mode++)
		{
			case 'm':
				memcpy(pos, ch.ptr, ch.len); 
				pos += ch.len;
				free(ch.ptr);
				break;
			case 'c':
			default:
				memcpy(pos, ch.ptr, ch.len); 
				pos += ch.len;
		}
	}
	va_end(chunks);
	
	return construct;
}

/**
 * convert a MP integer into a DER coded ASN.1 object
 */
chunk_t asn1_integer_from_mpz(const mpz_t value)
{
	size_t bits = mpz_sizeinbase(value, 2);  /* size in bits */
	chunk_t n;
	n.len = 1 + bits / 8;  /* size in bytes */	
	n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, value);
	
	return asn1_wrap(ASN1_INTEGER, "m", n);
}

/**
 *  convert a date into ASN.1 UTCTIME or GENERALIZEDTIME format
 */
chunk_t timetoasn1(const time_t *time, asn1_t type)
{
	int offset;
	const char *format;
	char buf[TIMETOA_BUF];
	chunk_t formatted_time;
	struct tm *t = gmtime(time);
	
	if (type == ASN1_GENERALIZEDTIME)
	{
		format = "%04d%02d%02d%02d%02d%02dZ";
		offset = 1900;
	}
	else /* ASN1_UTCTIME */
	{
		format = "%02d%02d%02d%02d%02d%02dZ";
		offset = (t->tm_year < 100)? 0 : -100;
	}
	sprintf(buf, format, t->tm_year + offset, t->tm_mon + 1, t->tm_mday
			, t->tm_hour, t->tm_min, t->tm_sec);
	formatted_time.ptr = buf;
	formatted_time.len = strlen(buf);
	return asn1_simple_object(type, formatted_time);
}
