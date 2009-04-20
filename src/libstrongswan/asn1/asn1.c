/*
 * Copyright (C) 2006 Martin Will
 * Copyright (C) 2000-2008 Andreas Steffen
 *
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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <utils.h>
#include <debug.h>

#include "oid.h"
#include "asn1.h"
#include "asn1_parser.h"

/**
 * some common prefabricated ASN.1 constants
 */
static u_char ASN1_INTEGER_0_str[] = { 0x02, 0x00 };
static u_char ASN1_INTEGER_1_str[] = { 0x02, 0x01, 0x01 };
static u_char ASN1_INTEGER_2_str[] = { 0x02, 0x01, 0x02 };

const chunk_t ASN1_INTEGER_0 = chunk_from_buf(ASN1_INTEGER_0_str);
const chunk_t ASN1_INTEGER_1 = chunk_from_buf(ASN1_INTEGER_1_str);
const chunk_t ASN1_INTEGER_2 = chunk_from_buf(ASN1_INTEGER_2_str);

/**
 * some popular algorithmIdentifiers
 */

static u_char ASN1_md2_id_str[] = {
	0x30, 0x0c,
		  0x06, 0x08,
				0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02,
		  0x05,0x00,
};

static u_char ASN1_md5_id_str[] = {
	0x30, 0x0C,
		  0x06, 0x08,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05,
		  0x05, 0x00
};

static u_char ASN1_sha1_id_str[] = {
	0x30, 0x09,
		  0x06, 0x05,
				0x2B, 0x0E,0x03, 0x02, 0x1A,
		  0x05, 0x00
};

static u_char ASN1_sha256_id_str[] = {
	0x30, 0x0d,
		  0x06, 0x09,
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
		  0x05, 0x00
};

static u_char ASN1_sha384_id_str[] = {
	0x30, 0x0d,
		  0x06, 0x09,
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
		  0x05, 0x00
};

static u_char ASN1_sha512_id_str[] = {
	0x30, 0x0d,
		  0x06, 0x09,
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
		  0x05,0x00
};

static u_char ASN1_md2WithRSA_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02,
		  0x05, 0x00
};

static u_char ASN1_md5WithRSA_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04,
		  0x05, 0x00
};

static u_char ASN1_sha1WithRSA_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
		  0x05, 0x00
};

static u_char ASN1_sha256WithRSA_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
		  0x05, 0x00
};

static u_char ASN1_sha384WithRSA_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C,
		  0x05, 0x00
};

static u_char ASN1_sha512WithRSA_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D,
		  0x05, 0x00
};

static u_char ASN1_rsaEncryption_id_str[] = {
	0x30, 0x0D,
		  0x06, 0x09,
				0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
		  0x05, 0x00
};

static const chunk_t ASN1_md2_id    = chunk_from_buf(ASN1_md2_id_str);
static const chunk_t ASN1_md5_id    = chunk_from_buf(ASN1_md5_id_str);
static const chunk_t ASN1_sha1_id   = chunk_from_buf(ASN1_sha1_id_str);
static const chunk_t ASN1_sha256_id = chunk_from_buf(ASN1_sha256_id_str);
static const chunk_t ASN1_sha384_id = chunk_from_buf(ASN1_sha384_id_str);
static const chunk_t ASN1_sha512_id = chunk_from_buf(ASN1_sha512_id_str);
static const chunk_t ASN1_rsaEncryption_id = chunk_from_buf(ASN1_rsaEncryption_id_str);
static const chunk_t ASN1_md2WithRSA_id = chunk_from_buf(ASN1_md2WithRSA_id_str);
static const chunk_t ASN1_md5WithRSA_id = chunk_from_buf(ASN1_md5WithRSA_id_str);
static const chunk_t ASN1_sha1WithRSA_id = chunk_from_buf(ASN1_sha1WithRSA_id_str);
static const chunk_t ASN1_sha256WithRSA_id = chunk_from_buf(ASN1_sha256WithRSA_id_str);
static const chunk_t ASN1_sha384WithRSA_id = chunk_from_buf(ASN1_sha384WithRSA_id_str);
static const chunk_t ASN1_sha512WithRSA_id = chunk_from_buf(ASN1_sha512WithRSA_id_str);

/*
 * Defined in header.
 */
chunk_t asn1_algorithmIdentifier(int oid)
{
	switch (oid)
	{
		case OID_RSA_ENCRYPTION:
			return ASN1_rsaEncryption_id;
		case OID_MD2_WITH_RSA:
			return ASN1_md2WithRSA_id;
		case OID_MD5_WITH_RSA:
			return ASN1_md5WithRSA_id;
		case OID_SHA1_WITH_RSA:
			return ASN1_sha1WithRSA_id;
		case OID_SHA256_WITH_RSA:
			return ASN1_sha256WithRSA_id;
		case OID_SHA384_WITH_RSA:
			return ASN1_sha384WithRSA_id;
		case OID_SHA512_WITH_RSA:
			return ASN1_sha512WithRSA_id;
		case OID_MD2:
			return ASN1_md2_id;
		case OID_MD5:
			return ASN1_md5_id;
		case OID_SHA1:
			return ASN1_sha1_id;
		case OID_SHA256:
			return ASN1_sha256_id;
		case OID_SHA384:
			return ASN1_sha384_id;
		case OID_SHA512:
			return ASN1_sha512_id;
		default:
			return chunk_empty;
	}
}

/*
 * Defined in header.
 */
int asn1_known_oid(chunk_t object)
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
			{
				oid = oid_names[oid].next;
			}
			else
			{
				return OID_UNKNOWN;
			}
		}
	}
	return -1;
}

/*
 * Defined in header.
 */
chunk_t asn1_build_known_oid(int n)
{
	chunk_t oid;
	int i;
	
	if (n < 0 || n >= OID_MAX)
	{
		return chunk_empty;
	}
	
	i = oid_names[n].level + 1;
	oid = chunk_alloc(2 + i);
	oid.ptr[0] = ASN1_OID;
	oid.ptr[1] = i;
	
	do
	{
		if (oid_names[n].level >= i)
		{
			n--;
			continue;
		}
		oid.ptr[--i + 2] = oid_names[n--].octet;
	}
	while (i > 0);
	
	return oid;
}

/*
 * Defined in header.
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
		DBG2("number of length octets is larger than ASN.1 object");
		return ASN1_INVALID_LENGTH;
	}
	
	if (n > sizeof(len))
	{
		DBG2("number of length octets is larger than limit of %d octets", 
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

#define TIME_MAX	0x7fffffff

/**
 * Converts ASN.1 UTCTIME or GENERALIZEDTIME into calender time
 */
time_t asn1_to_time(const chunk_t *utctime, asn1_t type)
{
	struct tm t;
	time_t tc, tz_offset;
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
	
	/* parse ASN.1 time string */
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
	
	/* convert to time_t */
	tc = mktime(&t);

	/* if no conversion overflow occurred, compensate timezone */
	return (tc == -1) ? TIME_MAX : (tc - timezone - tz_offset);
}

/**
 *  Convert a date into ASN.1 UTCTIME or GENERALIZEDTIME format
 */
chunk_t asn1_from_time(const time_t *time, asn1_t type)
{
	int offset;
	const char *format;
	char buf[BUF_LEN];
	chunk_t formatted_time;
	struct tm t;
	
	gmtime_r(time, &t);
	if (type == ASN1_GENERALIZEDTIME)
	{
		format = "%04d%02d%02d%02d%02d%02dZ";
		offset = 1900;
	}
	else /* ASN1_UTCTIME */
	{
		format = "%02d%02d%02d%02d%02d%02dZ";
		offset = (t.tm_year < 100)? 0 : -100;
	}
	snprintf(buf, BUF_LEN, format, t.tm_year + offset, 
			 t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
	formatted_time.ptr = buf;
	formatted_time.len = strlen(buf);
	return asn1_simple_object(type, formatted_time);
}

/*
 * Defined in header.
 */
void asn1_debug_simple_object(chunk_t object, asn1_t type, bool private)
{
	int oid;
	
	switch (type)
	{
		case ASN1_OID:
			oid = asn1_known_oid(object);
			if (oid != OID_UNKNOWN)
			{
				DBG2("  '%s'", oid_names[oid].name);
				return;
			}
			break;
		case ASN1_UTF8STRING:
		case ASN1_IA5STRING:
		case ASN1_PRINTABLESTRING:
		case ASN1_T61STRING:
		case ASN1_VISIBLESTRING:
			DBG2("  '%.*s'", (int)object.len, object.ptr);
			return;
		case ASN1_UTCTIME:
		case ASN1_GENERALIZEDTIME:
			{
				time_t time = asn1_to_time(&object, type);

				DBG2("  '%T'", &time, TRUE);
			}
			return;
		default:
			break;
	}
	if (private)
	{
		DBG4("%B", &object);
	}
	else
	{
		DBG3("%B", &object);
	}
}

/**
 * parse an ASN.1 simple type
 */
bool asn1_parse_simple_object(chunk_t *object, asn1_t type, u_int level, const char* name)
{
	size_t len;
	
	/* an ASN.1 object must possess at least a tag and length field */
	if (object->len < 2)
	{
		DBG2("L%d - %s:  ASN.1 object smaller than 2 octets", level, name);
		return FALSE;
	}
	
	if (*object->ptr != type)
	{
		DBG2("L%d - %s: ASN1 tag 0x%02x expected, but is 0x%02x",
			 level, name, type, *object->ptr);
		return FALSE;
	}
	
	len = asn1_length(object);
	
	if (len == ASN1_INVALID_LENGTH || object->len < len)
	{
		DBG2("L%d - %s:  length of ASN.1 object invalid or too large",
			 level, name);
		return FALSE;
	}
	
	DBG2("L%d - %s:", level, name);
	asn1_debug_simple_object(*object, type, FALSE);
	return TRUE;
}

/**
 * ASN.1 definition of an algorithmIdentifier
 */
static const asn1Object_t algorithmIdentifierObjects[] = {
	{ 0, "algorithmIdentifier",	ASN1_SEQUENCE,	ASN1_NONE         }, /* 0 */
	{ 1,   "algorithm",			ASN1_OID,		ASN1_BODY         }, /* 1 */
	{ 1,   "parameters",		ASN1_EOC,		ASN1_RAW|ASN1_OPT }, /* 2 */
	{ 1,   "end opt",			ASN1_EOC,		ASN1_END  	      }, /* 3 */
	{ 0, "exit",				ASN1_EOC,		ASN1_EXIT         }
};
#define ALGORITHM_ID_ALG			1
#define ALGORITHM_ID_PARAMETERS		2

/*
 * Defined in header
 */
int asn1_parse_algorithmIdentifier(chunk_t blob, int level0, chunk_t *parameters)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int alg = OID_UNKNOWN;
	
	parser = asn1_parser_create(algorithmIdentifierObjects, blob);
	parser->set_top_level(parser, level0);
	
	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case ALGORITHM_ID_ALG:
				alg = asn1_known_oid(object);
				break;
			case ALGORITHM_ID_PARAMETERS:
				if (parameters != NULL)
				{
					*parameters = object;
				}
				break;
			default:
				break;
		}
	}
	parser->destroy(parser);
	return alg;
}

/*
 *  tests if a blob contains a valid ASN.1 set or sequence
 */
bool is_asn1(chunk_t blob)
{
	u_int len;
	u_char tag = *blob.ptr;

	if (tag != ASN1_SEQUENCE && tag != ASN1_SET)
	{
		DBG2("  file content is not binary ASN.1");
		return FALSE;
	}

	len = asn1_length(&blob);

	/* exact match */
	if (len == blob.len)
	{
		return TRUE;
	}

	/* some websites append a surplus newline character to the blob */
	if (len + 1 == blob.len && *(blob.ptr + len) == '\n')
	{
		return TRUE;
	}

	DBG2("  file size does not match ASN.1 coded length");
	return FALSE;
}

/*
 * Defined in header.
 */
bool asn1_is_printablestring(chunk_t str)
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
 * codes ASN.1 lengths up to a size of 16'777'215 bytes
 */
static void asn1_code_length(size_t length, chunk_t *code)
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
u_char* asn1_build_object(chunk_t *object, asn1_t type, size_t datalen)
{
	u_char length_buf[4];
	chunk_t length = { length_buf, 0 };
	u_char *pos;
	
	/* code the asn.1 length field */
	asn1_code_length(datalen, &length);
	
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
 * Build a simple ASN.1 object
 */
chunk_t asn1_simple_object(asn1_t tag, chunk_t content)
{
	chunk_t object;
	
	u_char *pos = asn1_build_object(&object, tag, content.len);
	memcpy(pos, content.ptr, content.len); 
	pos += content.len;
	
	return object;
}

/**
 * Build an ASN.1 BITSTRING object
 */
chunk_t asn1_bitstring(const char *mode, chunk_t content)
{
	chunk_t object;
	u_char *pos = asn1_build_object(&object, ASN1_BIT_STRING, 1 + content.len);

	*pos++ = 0x00;
	memcpy(pos, content.ptr, content.len);
	if (*mode == 'm')
	{
		free(content.ptr);
	}
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
	pos = asn1_build_object(&construct, type, construct.len);
	
	/* copy or move the chunks */
	va_start(chunks, mode);
	for (i = 0; i < count; i++)
	{
		chunk_t ch = va_arg(chunks, chunk_t);
		
		memcpy(pos, ch.ptr, ch.len);
		pos += ch.len;

		if (*mode++ == 'm')
		{
			free(ch.ptr);
		}
	}
	va_end(chunks);
	
	return construct;
}

/**
 * ASN.1 definition of time
 */
static const asn1Object_t timeObjects[] = {
	{ 0, "utcTime",			ASN1_UTCTIME,			ASN1_OPT|ASN1_BODY 	}, /* 0 */
	{ 0, "end opt",			ASN1_EOC,				ASN1_END  			}, /* 1 */
	{ 0, "generalizeTime",	ASN1_GENERALIZEDTIME,	ASN1_OPT|ASN1_BODY 	}, /* 2 */
	{ 0, "end opt",			ASN1_EOC,				ASN1_END  			}, /* 3 */
	{ 0, "exit",			ASN1_EOC,				ASN1_EXIT  			}
};
#define TIME_UTC			0
#define TIME_GENERALIZED	2

/**
 * extracts and converts a UTCTIME or GENERALIZEDTIME object
 */
time_t asn1_parse_time(chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	time_t utc_time = 0;
	
	parser= asn1_parser_create(timeObjects, blob);
	parser->set_top_level(parser, level0);
	
	while (parser->iterate(parser, &objectID, &object))
	{
		if (objectID == TIME_UTC || objectID == TIME_GENERALIZED)
		{
			utc_time = asn1_to_time(&object, (objectID == TIME_UTC)
									? ASN1_UTCTIME : ASN1_GENERALIZEDTIME);
		}
	}
	parser->destroy(parser);
	return utc_time;
}
