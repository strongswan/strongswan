/**
 * @file identification.c
 * 
 * @brief Implementation of identification_t. 
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

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "definitions.h"
#include "identification.h"

#include <asn1/asn1.h>

/** 
 * String mappings for id_type_t.
 */

static const char *const id_type_name[] = {
	"ID_ANY",
	"ID_IPV4_ADDR",
	"ID_FQDN",
	"ID_RFC822_ADDR",
	"ID_IPV4_ADDR_SUBNET",
	"ID_IPV6_ADDR",
	"ID_IPV6_ADDR_SUBNET",
	"ID_IPV4_ADDR_RANGE",
	"ID_IPV6_ADDR_RANGE",
	"ID_DER_ASN1_DN",
	"ID_DER_ASN1_GN",
	"ID_KEY_ID",
};

enum_names id_type_names =
    { ID_ANY, ID_KEY_ID, id_type_name, NULL };

/**
 * X.501 acronyms for well known object identifiers (OIDs)
 */
static u_char oid_ND[]  = {
	0x02, 0x82, 0x06, 0x01, 0x0A, 0x07, 0x14
};
static u_char oid_UID[] = {
	0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01
};
static u_char oid_DC[]  = {
	0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19
};
static u_char oid_CN[] = {
	0x55, 0x04, 0x03
};
static u_char oid_S[] = {
	0x55, 0x04, 0x04
};
static u_char oid_SN[] = {
	0x55, 0x04, 0x05
};
static u_char oid_C[] = {
	0x55, 0x04, 0x06
};
static u_char oid_L[] = {
	0x55, 0x04, 0x07
};
static u_char oid_ST[] = {
	0x55, 0x04, 0x08
};
static u_char oid_O[] = {
	0x55, 0x04, 0x0A
};
static u_char oid_OU[] = {
	0x55, 0x04, 0x0B
};
static u_char oid_T[] = {
	0x55, 0x04, 0x0C
};
static u_char oid_D[] = {
	0x55, 0x04, 0x0D
};
static u_char oid_N[] = {
	0x55, 0x04, 0x29
};
static u_char oid_G[] = {
	0x55, 0x04, 0x2A
};
static u_char oid_I[] = {
	0x55, 0x04, 0x2B
};
static u_char oid_ID[] = {
	0x55, 0x04, 0x2D
};
static u_char oid_EN[]  = {
	0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x03, 0x01, 0x03
};
static u_char oid_E[] = {
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01
};
static u_char oid_UN[]  = {
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02
};
static u_char oid_TCGID[] = {
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x89, 0x31, 0x01, 0x01, 0x02, 0x02, 0x4B
};

/**
 * coding of X.501 distinguished name 
 */
typedef struct {
	const u_char *name;
	chunk_t oid;
	u_char type;
} x501rdn_t;

static const x501rdn_t x501rdns[] = {
	{"ND", 				{oid_ND,     7}, ASN1_PRINTABLESTRING},
	{"UID", 			{oid_UID,   10}, ASN1_PRINTABLESTRING},
	{"DC", 				{oid_DC,    10}, ASN1_PRINTABLESTRING},
	{"CN",				{oid_CN,     3}, ASN1_PRINTABLESTRING},
	{"S", 				{oid_S,      3}, ASN1_PRINTABLESTRING},
	{"SN", 				{oid_SN,     3}, ASN1_PRINTABLESTRING},
	{"serialNumber", 	{oid_SN,     3}, ASN1_PRINTABLESTRING},
	{"C", 				{oid_C,      3}, ASN1_PRINTABLESTRING},
	{"L", 				{oid_L,      3}, ASN1_PRINTABLESTRING},
	{"ST",				{oid_ST,     3}, ASN1_PRINTABLESTRING},
	{"O", 				{oid_O,      3}, ASN1_PRINTABLESTRING},
	{"OU", 				{oid_OU,     3}, ASN1_PRINTABLESTRING},
	{"T", 				{oid_T,      3}, ASN1_PRINTABLESTRING},
	{"D", 				{oid_D,      3}, ASN1_PRINTABLESTRING},
	{"N", 				{oid_N,      3}, ASN1_PRINTABLESTRING},
	{"G", 				{oid_G,      3}, ASN1_PRINTABLESTRING},
	{"I", 				{oid_I,      3}, ASN1_PRINTABLESTRING},
	{"ID", 				{oid_ID,     3}, ASN1_PRINTABLESTRING},
	{"EN", 				{oid_EN,    10}, ASN1_PRINTABLESTRING},
	{"employeeNumber",	{oid_EN,    10}, ASN1_PRINTABLESTRING},
	{"E", 				{oid_E,      9}, ASN1_IA5STRING},
	{"Email", 			{oid_E,      9}, ASN1_IA5STRING},
	{"emailAddress",	{oid_E,      9}, ASN1_IA5STRING},
	{"UN", 				{oid_UN,     9}, ASN1_IA5STRING},
	{"unstructuredName",{oid_UN,     9}, ASN1_IA5STRING},
	{"TCGID", 			{oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};
#define X501_RDN_ROOF   26

/**
 * maximum number of RDNs in atodn()
 */
#define RDN_MAX			20


typedef struct private_identification_t private_identification_t;

/**
 * Private data of an identification_t object.
 */
struct private_identification_t {
	/**
	 * Public interface.
	 */
	identification_t public;
	
	/**
	 * String representation of this ID.
	 */
	char *string;
	
	/**
	 * Encoded representation of this ID.
	 */
	chunk_t encoded;
	
	/**
	 * Type of this ID.
	 */
	id_type_t type;
};

static private_identification_t *identification_create(void);

/**
 * updates a chunk (!????)
 * TODO: We should reconsider this stuff, its not really clear
 */
static void update_chunk(chunk_t *ch, int n)
{
	n = (n > -1 && n < (int)ch->len)? n : (int)ch->len-1;
	ch->ptr += n; ch->len -= n;
}

/**
 * Prints a binary string in hexadecimal form
 */
void hex_str(chunk_t bin, chunk_t *str)
{
	u_int i;
	update_chunk(str, snprintf(str->ptr,str->len,"0x"));
	for (i = 0; i < bin.len; i++)
	{
		update_chunk(str, snprintf(str->ptr,str->len,"%02X",*bin.ptr++));
	}
}

/**
 * Pointer is set to the first RDN in a DN
 */
static status_t init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
	*rdn = CHUNK_INITIALIZER;
	*attribute = CHUNK_INITIALIZER;
	
	/* a DN is a SEQUENCE OF RDNs */
	if (*dn.ptr != ASN1_SEQUENCE)
	{
		/* DN is not a SEQUENCE */
		return FAILED;
	}
	
	rdn->len = asn1_length(&dn);
	
	if (rdn->len == ASN1_INVALID_LENGTH)
	{
		/* Invalid RDN length */
		return FAILED;
	}
	
	rdn->ptr = dn.ptr;
	
	/* are there any RDNs ? */
	*next = rdn->len > 0;
	
	return SUCCESS;
}

/**
 * Fetches the next RDN in a DN
 */
static status_t get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid, chunk_t *value, asn1_t *type, bool *next)
{
	chunk_t body;

	/* initialize return values */
	*oid   = CHUNK_INITIALIZER;
	*value = CHUNK_INITIALIZER;

	/* if all attributes have been parsed, get next rdn */
	if (attribute->len <= 0)
	{
		/* an RDN is a SET OF attributeTypeAndValue */
		if (*rdn->ptr != ASN1_SET)
		{
			/* RDN is not a SET */
			return FAILED;
		}
		attribute->len = asn1_length(rdn);
		if (attribute->len == ASN1_INVALID_LENGTH)
		{
			/* Invalid attribute length */
			return FAILED;
		}
		attribute->ptr = rdn->ptr;
		/* advance to start of next RDN */
		rdn->ptr += attribute->len;
		rdn->len -= attribute->len;
	}
	
	/* an attributeTypeAndValue is a SEQUENCE */
	if (*attribute->ptr != ASN1_SEQUENCE)
	{
		/* attributeTypeAndValue is not a SEQUENCE */
		return FAILED;
	}
	
	/* extract the attribute body */
	body.len = asn1_length(attribute);
	
	if (body.len == ASN1_INVALID_LENGTH)
	{
		/* Invalid attribute body length */
		return FAILED;
	}
	
	body.ptr = attribute->ptr;
	
	/* advance to start of next attribute */
	attribute->ptr += body.len;
	attribute->len -= body.len;
	
	/* attribute type is an OID */
	if (*body.ptr != ASN1_OID)
	{
		/* attributeType is not an OID */
		return FAILED;
	}
	/* extract OID */
	oid->len = asn1_length(&body);
	
	if (oid->len == ASN1_INVALID_LENGTH)
	{
		/* Invalid attribute OID length */
		return FAILED;
	}
	oid->ptr = body.ptr;
	
	/* advance to the attribute value */
	body.ptr += oid->len;
	body.len -= oid->len;

	/* extract string type */
	*type = *body.ptr;
	
	/* extract string value */
	value->len = asn1_length(&body);
	
	if (value->len == ASN1_INVALID_LENGTH)
	{
		/* Invalid attribute string length */
		return FAILED;
	}
	value->ptr = body.ptr;
	
	/* are there any RDNs left? */
	*next = rdn->len > 0 || attribute->len > 0;
	return SUCCESS;
}

/**
 * Parses an ASN.1 distinguished name int its OID/value pairs
 */
static status_t dntoa(chunk_t dn, chunk_t *str)
{
	chunk_t rdn, oid, attribute, value;
	asn1_t type;
	int oid_code;
	bool next;
	bool first = TRUE;

	status_t status = init_rdn(dn, &rdn, &attribute, &next);

	if (status != SUCCESS)
		return status;

	while (next)
	{
		status = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

		if (status != SUCCESS)
			return status;

		if (first) 
		{ /* first OID/value pair */
			first = FALSE;
		}
		else
		{ /* separate OID/value pair by a comma */
			update_chunk(str, snprintf(str->ptr,str->len,", "));
		}

		/* print OID */
		oid_code = known_oid(oid);
		if (oid_code == OID_UNKNOWN) 
		{ /* OID not found in list */
			hex_str(oid, str);
		}
		else
		{
			update_chunk(str, snprintf(str->ptr,str->len,"%s", oid_names[oid_code].name));
		}
		/* print value */
		update_chunk(str, snprintf(str->ptr,str->len,"=%.*s", (int)value.len,value.ptr));
	}
	return SUCCESS;
}

/**
 * compare two distinguished names by
 * comparing the individual RDNs
 */
static bool same_dn(chunk_t a, chunk_t b)
{
	chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
	chunk_t oid_a, oid_b, value_a, value_b;
	asn1_t type_a, type_b;
	bool next_a, next_b;

	/* same lengths for the DNs */
	if (a.len != b.len)
		return FALSE;

	/* try a binary comparison first */
	if (memeq(a.ptr, b.ptr, b.len))
		return TRUE;
 
	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != SUCCESS
	||	init_rdn(b, &rdn_b, &attribute_b, &next_b) != SUCCESS)
	{
		return FALSE;
	}

	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != SUCCESS 
		||  get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != SUCCESS)
		{
			return FALSE;
		}

		/* OIDs must agree */
		if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
			return FALSE;

		/* same lengths for values */
		if (value_a.len != value_b.len)
			return FALSE;

		/* printableStrings and email RDNs require uppercase comparison */
		if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING
		|| (type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
		{
			if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
				return FALSE;
		}
		else
		{
			if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
				return FALSE;
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b)
		return FALSE;

	/* the two DNs are equal! */
	return TRUE;
}


/**
 * compare two distinguished names by comparing the individual RDNs.
 * A single'*' character designates a wildcard RDN in DN b.
 * TODO: Add support for different RDN order in DN !!
 */
bool match_dn(chunk_t a, chunk_t b, int *wildcards)
{
	chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
	chunk_t oid_a, oid_b, value_a, value_b;
	asn1_t type_a,  type_b;
	bool next_a, next_b;

	/* initialize wildcard counter */
	*wildcards = 0;

	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != SUCCESS
	||	init_rdn(b, &rdn_b, &attribute_b, &next_b) != SUCCESS)
	{
		return FALSE;
	}

	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != SUCCESS
		||	get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != SUCCESS)
		{
			return FALSE;
		}
		/* OIDs must agree */
		if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
			return FALSE;

		/* does rdn_b contain a wildcard? */
		if (value_b.len == 1 && *value_b.ptr == '*')
		{
			(*wildcards)++;
			continue;
		}
		/* same lengths for values */
		if (value_a.len != value_b.len)
			return FALSE;

		/* printableStrings and email RDNs require uppercase comparison */
		if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING
		|| (type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
		{
			if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
				return FALSE;
		}
		else
		{
			if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
				return FALSE;
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b)
	{
		return FALSE;
	}

	/* the two DNs match! */
	*wildcards = min(*wildcards, MAX_WILDCARDS);
	return TRUE;
}

/**
 * Converts an LDAP-style human-readable ASCII-encoded
 * ASN.1 distinguished name into binary DER-encoded format
 */
static status_t atodn(char *src, chunk_t *dn)
{
	/* finite state machine for atodn */
	typedef enum {
		SEARCH_OID =	0,
		READ_OID =		1,
		SEARCH_NAME =	2,
		READ_NAME =		3,
		UNKNOWN_OID =	4
	} state_t;
	
	chunk_t oid  = CHUNK_INITIALIZER;
	chunk_t name = CHUNK_INITIALIZER;
	chunk_t rdns[RDN_MAX];
	int rdn_count = 0;
	int dn_len = 0;
	int whitespace = 0;
	int i = 0;
	asn1_t rdn_type;
	state_t state = SEARCH_OID;
	status_t status = SUCCESS;
	
	do
	{
		switch (state)
		{
			case SEARCH_OID:
				if (*src != ' ' && *src != '/' && *src !=  ',')
				{
					oid.ptr = src;
					oid.len = 1;
					state = READ_OID;
				}
				break;
			case READ_OID:
				if (*src != ' ' && *src != '=')
				{
					oid.len++;
				}
				else
				{
					for (i = 0; i < X501_RDN_ROOF; i++)
					{
						if (strlen(x501rdns[i].name) == oid.len
						&&  strncasecmp(x501rdns[i].name, oid.ptr, oid.len) == 0)
						{
							break; /* found a valid OID */
						}
					}
					if (i == X501_RDN_ROOF)
					{
						status = NOT_SUPPORTED;
						state = UNKNOWN_OID;
						break;
					}
					/* reset oid and change state */
					oid = CHUNK_INITIALIZER;
					state = SEARCH_NAME;
				}
				break;
			case SEARCH_NAME:
				if (*src != ' ' && *src != '=')
				{
					name.ptr = src;
					name.len = 1;
					whitespace = 0;
					state = READ_NAME;
				}
				break;
			case READ_NAME:
				if (*src != ',' && *src != '/' && *src != '\0')
				{
					name.len++;
					if (*src == ' ')
						whitespace++;
					else
						whitespace = 0;
				}
				else
				{
					name.len -= whitespace;
					rdn_type = (x501rdns[i].type == ASN1_PRINTABLESTRING
							&& !is_printablestring(name))? ASN1_T61STRING : x501rdns[i].type;
					
					if (rdn_count < RDN_MAX)
					{
						rdns[rdn_count] = 
								asn1_wrap(ASN1_SET, "m",
									asn1_wrap(ASN1_SEQUENCE, "mm",
										asn1_wrap(ASN1_OID, "c", x501rdns[i].oid),
										asn1_wrap(rdn_type, "c", name)
									)
								);
						dn_len += rdns[rdn_count++].len;
					}
					else
					{
						status = OUT_OF_RES;
					}
					/* reset name and change state */
					name = CHUNK_INITIALIZER;
					state = SEARCH_OID;
				}
				break;
			case UNKNOWN_OID:
				break;
		}
	} while (*src++ != '\0');

	/* build the distinguished name sequence */
   {
		int i;
		u_char *pos = build_asn1_object(dn, ASN1_SEQUENCE, dn_len);

		for (i = 0; i < rdn_count; i++)
		{
			memcpy(pos, rdns[i].ptr, rdns[i].len); 
			pos += rdns[i].len;
			free(rdns[i].ptr);
		}
	}

	if (status != SUCCESS)
	{
		free(dn->ptr);
		*dn = CHUNK_INITIALIZER;
	}
	return status;
}

/**
 * Implementation of identification_t.get_encoding.
 */
static chunk_t get_encoding(private_identification_t *this)
{
	return this->encoded;
}

/**
 * Implementation of identification_t.get_type.
 */
static id_type_t get_type(private_identification_t *this)
{
	return this->type;
}
	
/**
 * Implementation of identification_t.get_string.
 */
static char *get_string(private_identification_t *this)
{
	return this->string;
}

/**
 * Implementation of identification_t.contains_wildcards.
 */
static bool contains_wildcards(private_identification_t *this)
{
	return this->type == ID_ANY || strchr(this->string, '*') != NULL;
}

/**
 * Default implementation of identification_t.equals.
 * compares encoded chunk for equality.
 */
static bool equals_binary(private_identification_t *this, private_identification_t *other)
{
	return this->type == other->type && chunk_equals(this->encoded, other->encoded);
}

/**
 * Special implementation of identification_t.equals for ID_DER_ASN1_DN.
 */
static bool equals_dn(private_identification_t *this, private_identification_t *other)
{
	return same_dn(this->encoded, other->encoded);
}

/**
 * Default implementation of identification_t.matches.
 */
static bool matches_binary(private_identification_t *this, private_identification_t *other,
	int *wildcards)
{	
	if (other->type == ID_ANY)
	{
		*wildcards = MAX_WILDCARDS;
		return TRUE;
	}
	*wildcards = 0;
	return this->type == other->type && chunk_equals(this->encoded, other->encoded);
}

/**
 * Special implementation of identification_t.matches for ID_RFC822_ADDR/ID_FQDN.
 * Checks for a wildcard in other-string, and compares it against this-string.
 */
static bool matches_string(private_identification_t *this, private_identification_t *other,
	int *wildcards)
{
	u_int len = other->encoded.len;
	
	if (other->type == ID_ANY)
	{
		*wildcards = MAX_WILDCARDS;
		return TRUE;
	}
	
	if (this->type != other->type)
		return FALSE;

	/* try a binary comparison first */
	if (equals_binary(this, other))
	{
		*wildcards = 0;
		return TRUE;
	}
	
	if (len == 0 || this->encoded.len < len)
		return FALSE;

	/* check for single wildcard at the head of the string */
	if (*other->encoded.ptr == '*')
	{
		*wildcards = 1;

		/* single asterisk matches any string */
		if (len-- == 1)
			return TRUE;

		if (memeq(this->encoded.ptr + this->encoded.len - len, other->encoded.ptr + 1, len))
			return TRUE;
	}
	
	return FALSE;
}

/**
 * Special implementation of identification_t.matches for ID_ANY.
 * ANY matches only another ANY, but nothing other
 */
static bool matches_any(private_identification_t *this, private_identification_t *other,
	int *wildcards)
{	
	*wildcards = 0;
	return other->type == ID_ANY;
}

/**
 * Special implementation of identification_t.matches for ID_DER_ASN1_DN.
 * ANY matches any, even ANY, thats why its there...
 */
static bool matches_dn(private_identification_t *this, private_identification_t *other,
	int *wildcards)
{
	if (other->type == ID_ANY)
	{
		*wildcards = MAX_WILDCARDS;
		return TRUE;
	}
	
	if (this->type == other->type)
	{
		return match_dn(this->encoded, other->encoded, wildcards);
	}
	return FALSE;
}

/**
 * Implementation of identification_t.clone.
 */
static identification_t *clone(private_identification_t *this)
{
	private_identification_t *clone = identification_create();
	
	clone->type = this->type;
	clone->encoded = chunk_clone(this->encoded);
	clone->string = malloc(strlen(this->string) + 1);
	strcpy(clone->string, this->string);
	
	clone->public.equals = this->public.equals;
	clone->public.matches = this->public.matches;
	
	return &clone->public;
}

/**
 * Implementation of identification_t.destroy.
 */
static void destroy(private_identification_t *this)
{
	free(this->string);
	free(this->encoded.ptr);
	free(this);	
}

/**
 * Generic constructor used for the other constructors.
 */
static private_identification_t *identification_create(void)
{
	private_identification_t *this = malloc_thing(private_identification_t);
	
	this->public.get_encoding = (chunk_t (*) (identification_t*))get_encoding;
	this->public.get_type = (id_type_t (*) (identification_t*))get_type;
	this->public.get_string = (char* (*) (identification_t*))get_string;
	this->public.contains_wildcards = (bool (*) (identification_t *this))contains_wildcards;
	this->public.clone = (identification_t* (*) (identification_t*))clone;
	this->public.destroy = (void (*) (identification_t*))destroy;
	/* we use these as defaults, the may be overloaded for special ID types */
	this->public.equals = (bool (*) (identification_t*,identification_t*))equals_binary;
	this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_binary;
	
	this->string = NULL;
	this->encoded = CHUNK_INITIALIZER;
	
	return this;
}

/*
 * Described in header.
 */
identification_t *identification_create_from_string(char *string)
{
	private_identification_t *this = identification_create();

	if (string == NULL)
		string = "%any";
	
	if (strchr(string, '=') != NULL)
	{
		/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN.
		 * convert from LDAP style or openssl x509 -subject style to ASN.1 DN
		 */
		if (atodn(string, &this->encoded) != SUCCESS)
		{
			free(this);
			return NULL;
		}
		this->string = strdup(string);
		this->type = ID_DER_ASN1_DN;
		this->public.equals = (bool (*) (identification_t*,identification_t*))equals_dn;
		this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_dn;
		return &this->public;
	}
	else if (strchr(string, '@') == NULL)
	{
		if (streq(string, "%any")
		||	streq(string, "0.0.0.0")
		||	streq(string, "*")
		||	streq(string, "::")
		||	streq(string, "0::0"))
		{
			/* any ID will be accepted */
			this->type = ID_ANY;
			this->string = strdup("%any");
			this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_any;
			return &this->public;
		}
		else
		{
			if (strchr(string, ':') == NULL)
			{
				/* try IPv4 */
				struct in_addr address;
				chunk_t chunk = {(void*)&address, sizeof(address)};
				
				if (inet_pton(AF_INET, string, &address) <= 0)
				{
					free(this);
					return NULL;
				}
				this->encoded = chunk_clone(chunk);
				this->string = strdup(string);
				this->type = ID_IPV4_ADDR;
				return &(this->public);
			}
			else
			{
				/* try IPv6 */
				struct in6_addr address;
				chunk_t chunk = {(void*)&address, sizeof(address)};
				
				if (inet_pton(AF_INET6, string, &address) <= 0)
				{
					free(this);
					return NULL;
				}
				this->encoded = chunk_clone(chunk);
				this->string = strdup(string);
				this->type = ID_IPV6_ADDR;
				return &(this->public);
			}
		}
	}
	else
	{
		if (*string == '@')
		{
			if (*(string + 1) == '#')
			{
				/* TODO: Pluto handles '#' as hex encoded ID_KEY_ID. */
				free(this);
				return NULL;
			}
			else
			{
				this->type = ID_FQDN;
				this->string = strdup(string);
				this->encoded.ptr = strdup(string + 1);
				this->encoded.len = strlen(string + 1);
				this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_string;
				return &(this->public);
			}
		}
		else
		{
			this->type = ID_RFC822_ADDR;
			this->string = strdup(string);
			this->encoded.ptr = strdup(string);
			this->encoded.len = strlen(string);
			this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_string;
			return &(this->public);
		}
	}
}

/*
 * Described in header.
 */
identification_t *identification_create_from_encoding(id_type_t type, chunk_t encoded)
{
	char *pos;
	char buf[BUF_LEN];
	chunk_t buf_chunk = chunk_from_buf(buf);
	private_identification_t *this = identification_create();
	
	this->type = type;

	switch (type)
	{
		case ID_ANY:
			this->string = strdup("%any");
			this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_any;
			break;
		case ID_IPV4_ADDR:
			if (encoded.len < sizeof(struct in_addr) ||
				inet_ntop(AF_INET, encoded.ptr, buf, sizeof(buf)) == NULL)
			{
				this->string = strdup("(invalid ID_IPV4_ADDR)");
			}
			else
			{
				this->string = strdup(buf);
			}
			break;
		case ID_IPV6_ADDR:
			if (encoded.len < sizeof(struct in6_addr) ||
				inet_ntop(AF_INET6, encoded.ptr, buf, INET6_ADDRSTRLEN) == NULL)
			{
				this->string = strdup("(invalid ID_IPV6_ADDR)");
			}
			else
			{
				this->string = strdup(buf);
			}
			break;
		case ID_FQDN:
			snprintf(buf, sizeof(buf), "@%.*s", encoded.len, encoded.ptr);
			this->string = strdup(buf);
			this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_string;
			break;
		case ID_RFC822_ADDR:
			snprintf(buf, sizeof(buf), "%.*s", encoded.len, encoded.ptr);
			this->string = strdup(buf);
			this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_string;
			break;
		case ID_DER_ASN1_DN:
			snprintf(buf, sizeof(buf), "%.*s", encoded.len, encoded.ptr);
			/* TODO: whats returned on failure */
			dntoa(encoded, &buf_chunk);
			this->string = strdup(buf);
			this->public.equals = (bool (*) (identification_t*,identification_t*))equals_dn;
			this->public.matches = (bool (*) (identification_t*,identification_t*,int*))matches_dn;
			break;
		case ID_DER_ASN1_GN:
			this->string = strdup("ASN.1 coded generalName");
			break;
		case ID_KEY_ID:
			this->string = strdup("(KEY_ID)");
			break;
		case ID_DER_ASN1_GN_URI:
			snprintf(buf, sizeof(buf), "%.*s", encoded.len, encoded.ptr);
			this->string = strdup(buf);
			break;
		default:
			snprintf(buf, sizeof(buf), "(invalid ID type: %d)", type);
			this->string = strdup(buf);
			break;
	}
	
	/* apply encoded chunk */
	if (type != ID_ANY)
	{
		this->encoded = chunk_clone(encoded);
	}
	
	/* remove unprintable chars in string */
	for (pos = this->string; *pos != '\0'; pos++)
	{
		if (!isprint(*pos))
		{
			*pos = '?';
		}
	}
	return &(this->public);
}
