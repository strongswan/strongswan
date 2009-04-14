/*
 * Copyright (C) 2009 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "identification.h"

#include <asn1/oid.h>
#include <asn1/asn1.h>

ENUM_BEGIN(id_match_names, ID_MATCH_NONE, ID_MATCH_MAX_WILDCARDS,
	"MATCH_NONE",
	"MATCH_ANY",
	"MATCH_MAX_WILDCARDS");
ENUM_NEXT(id_match_names, ID_MATCH_PERFECT, ID_MATCH_PERFECT, ID_MATCH_MAX_WILDCARDS,
	"MATCH_PERFECT");
ENUM_END(id_match_names, ID_MATCH_PERFECT);

ENUM_BEGIN(id_type_names, ID_ANY, ID_KEY_ID,
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
	"ID_KEY_ID");
ENUM_NEXT(id_type_names, ID_DER_ASN1_GN_URI, ID_CERT_DER_SHA1, ID_KEY_ID,
	"ID_DER_ASN1_GN_URI",
	"ID_PUBKEY_INFO_SHA1",
	"ID_PUBKEY_SHA1",
	"ID_CERT_DER_SHA1");
ENUM_END(id_type_names, ID_CERT_DER_SHA1);

/**
 * coding of X.501 distinguished name 
 */
typedef struct {
	const u_char *name;
	int oid;
	u_char type;
} x501rdn_t;

static const x501rdn_t x501rdns[] = {
	{"ND", 				OID_NAME_DISTINGUISHER,		ASN1_PRINTABLESTRING},
	{"UID", 			OID_PILOT_USERID,			ASN1_PRINTABLESTRING},
	{"DC", 				OID_PILOT_DOMAIN_COMPONENT, ASN1_PRINTABLESTRING},
	{"CN",				OID_COMMON_NAME,			ASN1_PRINTABLESTRING},
	{"S", 				OID_SURNAME,				ASN1_PRINTABLESTRING},
	{"SN", 				OID_SERIAL_NUMBER,			ASN1_PRINTABLESTRING},
	{"serialNumber", 	OID_SERIAL_NUMBER,			ASN1_PRINTABLESTRING},
	{"C", 				OID_COUNTRY,				ASN1_PRINTABLESTRING},
	{"L", 				OID_LOCALITY,				ASN1_PRINTABLESTRING},
	{"ST",				OID_STATE_OR_PROVINCE,		ASN1_PRINTABLESTRING},
	{"O", 				OID_ORGANIZATION,			ASN1_PRINTABLESTRING},
	{"OU", 				OID_ORGANIZATION_UNIT,		ASN1_PRINTABLESTRING},
	{"T", 				OID_TITLE,					ASN1_PRINTABLESTRING},
	{"D", 				OID_DESCRIPTION,			ASN1_PRINTABLESTRING},
	{"N", 				OID_NAME,					ASN1_PRINTABLESTRING},
	{"G", 				OID_GIVEN_NAME,				ASN1_PRINTABLESTRING},
	{"I", 				OID_INITIALS,				ASN1_PRINTABLESTRING},
	{"ID", 				OID_UNIQUE_IDENTIFIER,		ASN1_PRINTABLESTRING},
	{"EN", 				OID_EMPLOYEE_NUMBER,		ASN1_PRINTABLESTRING},
	{"employeeNumber",	OID_EMPLOYEE_NUMBER,		ASN1_PRINTABLESTRING},
	{"E", 				OID_EMAIL_ADDRESS,			ASN1_IA5STRING},
	{"Email", 			OID_EMAIL_ADDRESS,			ASN1_IA5STRING},
	{"emailAddress",	OID_EMAIL_ADDRESS,			ASN1_IA5STRING},
	{"UN", 				OID_UNSTRUCTURED_NAME,		ASN1_IA5STRING},
	{"unstructuredName",OID_UNSTRUCTURED_NAME,		ASN1_IA5STRING},
	{"TCGID", 			OID_TCGID,					ASN1_PRINTABLESTRING}
};

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
 * Remove any malicious characters from a chunk. We are very restrictive, but
 * whe use these strings only to present it to the user.
 */
static bool sanitize_chunk(chunk_t chunk, chunk_t *clone)
{
	char *pos;
	bool all_printable = TRUE;
	
	*clone = chunk_clone(chunk);
	
	for (pos = clone->ptr; pos < (char*)(clone->ptr + clone->len); pos++)
	{
		if (!isprint(*pos))
		{
			*pos = '?';
			all_printable = FALSE;
		}
	}
	return all_printable;
}

/**
 * Pointer is set to the first RDN in a DN
 */
static bool init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
	*rdn = chunk_empty;
	*attribute = chunk_empty;
	
	/* a DN is a SEQUENCE OF RDNs */
	if (*dn.ptr != ASN1_SEQUENCE)
	{
		/* DN is not a SEQUENCE */
		return FALSE;
	}
	
	rdn->len = asn1_length(&dn);
	
	if (rdn->len == ASN1_INVALID_LENGTH)
	{
		/* Invalid RDN length */
		return FALSE;
	}
	
	rdn->ptr = dn.ptr;
	
	/* are there any RDNs ? */
	*next = rdn->len > 0;
	
	return TRUE;
}

/**
 * Fetches the next RDN in a DN
 */
static bool get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid,
						 chunk_t *value, asn1_t *type, bool *next)
{
	chunk_t body;
	
	/* initialize return values */
	*oid   = chunk_empty;
	*value = chunk_empty;
	
	/* if all attributes have been parsed, get next rdn */
	if (attribute->len <= 0)
	{
		/* an RDN is a SET OF attributeTypeAndValue */
		if (*rdn->ptr != ASN1_SET)
		{
			/* RDN is not a SET */
			return FALSE;
		}
		attribute->len = asn1_length(rdn);
		if (attribute->len == ASN1_INVALID_LENGTH)
		{
			/* Invalid attribute length */
			return FALSE;
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
		return FALSE;
	}
	
	/* extract the attribute body */
	body.len = asn1_length(attribute);
	
	if (body.len == ASN1_INVALID_LENGTH)
	{
		/* Invalid attribute body length */
		return FALSE;
	}
	
	body.ptr = attribute->ptr;
	
	/* advance to start of next attribute */
	attribute->ptr += body.len;
	attribute->len -= body.len;
	
	/* attribute type is an OID */
	if (*body.ptr != ASN1_OID)
	{
		/* attributeType is not an OID */
		return FALSE;
	}
	/* extract OID */
	oid->len = asn1_length(&body);
	
	if (oid->len == ASN1_INVALID_LENGTH)
	{
		/* Invalid attribute OID length */
		return FALSE;
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
		return FALSE;
	}
	value->ptr = body.ptr;
	
	/* are there any RDNs left? */
	*next = rdn->len > 0 || attribute->len > 0;
	return TRUE;
}

/**
 * Parses an ASN.1 distinguished name int its OID/value pairs
 */
static bool dntoa(chunk_t dn, chunk_t *str)
{
	chunk_t rdn, oid, attribute, value, proper;
	asn1_t type;
	int oid_code;
	bool next;
	bool first = TRUE;
	
	if (!init_rdn(dn, &rdn, &attribute, &next))
	{
		return FALSE;
	}
	
	while (next)
	{
		if (!get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next))
		{
			return FALSE;
		}
		
		if (first) 
		{ /* first OID/value pair */
			first = FALSE;
		}
		else
		{ /* separate OID/value pair by a comma */
			update_chunk(str, snprintf(str->ptr,str->len,", "));
		}
		
		/* print OID */
		oid_code = asn1_known_oid(oid);
		if (oid_code == OID_UNKNOWN)
		{
			update_chunk(str, snprintf(str->ptr,str->len,"0x#B", &oid));
		}
		else
		{
			update_chunk(str, snprintf(str->ptr,str->len,"%s", oid_names[oid_code].name));
		}
		/* print value */
		sanitize_chunk(value, &proper);
		update_chunk(str, snprintf(str->ptr,str->len,"=%.*s", (int)proper.len, proper.ptr));
		chunk_free(&proper);
	}
	return TRUE;
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
	{
		return FALSE;
	}
	/* try a binary comparison first */
	if (memeq(a.ptr, b.ptr, b.len))
	{
		return TRUE;
	}
	/* initialize DN parsing */
	if (!init_rdn(a, &rdn_a, &attribute_a, &next_a) ||
		!init_rdn(b, &rdn_b, &attribute_b, &next_b))
	{
		return FALSE;
	}
	
	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (!get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) || 
			!get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b))
		{
			return FALSE;
		}
		
		/* OIDs must agree */
		if (oid_a.len != oid_b.len || !memeq(oid_a.ptr, oid_b.ptr, oid_b.len))
		{
			return FALSE;
		}
		
		/* same lengths for values */
		if (value_a.len != value_b.len)
		{
			return FALSE;
		}
		
		/* printableStrings and email RDNs require uppercase comparison */
		if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
			(type_a == ASN1_IA5STRING && asn1_known_oid(oid_a) == OID_PKCS9_EMAIL)))
		{
			if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
			{
				return FALSE;
			}
		}
		else
		{
			if (!strneq(value_a.ptr, value_b.ptr, value_b.len))
			{
				return FALSE;	
			}
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b)
	{
		return FALSE;
	}
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
	if (!init_rdn(a, &rdn_a, &attribute_a, &next_a) ||
		!init_rdn(b, &rdn_b, &attribute_b, &next_b))
	{
		return FALSE;
	}
	
	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (!get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) ||
			!get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b))
		{
			return FALSE;
		}
		/* OIDs must agree */
		if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
		{
			return FALSE;
		}
		
		/* does rdn_b contain a wildcard? */
		if (value_b.len == 1 && *value_b.ptr == '*')
		{
			(*wildcards)++;
			continue;
		}
		/* same lengths for values */
		if (value_a.len != value_b.len)
		{
			return FALSE;
		}
		
		/* printableStrings and email RDNs require uppercase comparison */
		if (type_a == type_b && (type_a == ASN1_PRINTABLESTRING ||
			(type_a == ASN1_IA5STRING && asn1_known_oid(oid_a) == OID_PKCS9_EMAIL)))
		{
			if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
			{
				return FALSE;
			}
		}
		else
		{
			if (!strneq(value_a.ptr, value_b.ptr, value_b.len))
			{
				return FALSE;
			}
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b)
	{
		return FALSE;
	}
	/* the two DNs match! */
	*wildcards = min(*wildcards, ID_MATCH_ONE_WILDCARD - ID_MATCH_MAX_WILDCARDS);
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
	
	chunk_t oid  = chunk_empty;
	chunk_t name = chunk_empty;
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
					bool found = FALSE;
					
					for (i = 0; i < countof(x501rdns); i++)
					{
						if (strlen(x501rdns[i].name) == oid.len &&
							strncasecmp(x501rdns[i].name, oid.ptr, oid.len) == 0)
						{
							found = TRUE;
							break;
						}
					}
					if (!found)
					{
						status = NOT_SUPPORTED;
						state = UNKNOWN_OID;
						break;
					}
					/* reset oid and change state */
					oid = chunk_empty;
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
								&& !asn1_is_printablestring(name))
								? ASN1_T61STRING : x501rdns[i].type;
					
					if (rdn_count < RDN_MAX)
					{
						chunk_t rdn_oid;
						
						rdn_oid = asn1_get_known_oid(x501rdns[i].oid);
						if (rdn_oid.len)
						{
							rdns[rdn_count] = 
									asn1_wrap(ASN1_SET, "m",
										asn1_wrap(ASN1_SEQUENCE, "mm",
											asn1_wrap(ASN1_OID, "m", rdn_oid),
											asn1_wrap(rdn_type, "c", name)
										)
									);
							dn_len += rdns[rdn_count++].len;
						}
						else
						{
							status = INVALID_ARG;
						}
					}
					else
					{
						status = OUT_OF_RES;
					}
					/* reset name and change state */
					name = chunk_empty;
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
		u_char *pos = asn1_build_object(dn, ASN1_SEQUENCE, dn_len);
		
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
		*dn = chunk_empty;
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
 * Implementation of identification_t.contains_wildcards fro ID_DER_ASN1_DN.
 */
static bool contains_wildcards_dn(private_identification_t *this)
{
	chunk_t rdn, attribute;
	chunk_t oid, value;
	asn1_t type;
	bool next;
	
	if (!init_rdn(this->encoded, &rdn, &attribute, &next))
	{
		return FALSE;
	}	
	/* fetch next RDN */
	while (next)
	{
		/* parse next RDN and check for errors */
		if (!get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next))
		{
			return FALSE;
		}
		/* check if RDN is a wildcard */
		if (value.len == 1 && *value.ptr == '*')
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Implementation of identification_t.contains_wildcards.
 */
static bool contains_wildcards(private_identification_t *this)
{
	switch (this->type)
	{
		case ID_ANY:
			return TRUE;
		case ID_FQDN:
		case ID_RFC822_ADDR:
			return memchr(this->encoded.ptr, '*', this->encoded.len) != NULL;
		case ID_DER_ASN1_DN:
			return contains_wildcards_dn(this);
		default:
			return FALSE;
	}
}

/**
 * Default implementation of identification_t.equals.
 * compares encoded chunk for equality.
 */
static bool equals_binary(private_identification_t *this, private_identification_t *other)
{
	if (this->type == other->type)
	{
		if (this->type == ID_ANY)
		{
			return TRUE;
		}
		return chunk_equals(this->encoded, other->encoded);
	}
	return FALSE;						
}

/**
 * Special implementation of identification_t.equals for ID_DER_ASN1_DN.
 */
static bool equals_dn(private_identification_t *this,
					  private_identification_t *other)
{
	return same_dn(this->encoded, other->encoded);
}

/**
 * Special implementation of identification_t.equals for RFC822 and FQDN.
 */
static bool equals_strcasecmp(private_identification_t *this,
							  private_identification_t *other)
{
	/* we do some extra sanity checks to check for invalid IDs with a 
	 * terminating null in it. */
	if (this->encoded.len == other->encoded.len &&
		memchr(this->encoded.ptr, 0, this->encoded.len) == NULL &&
		memchr(other->encoded.ptr, 0, other->encoded.len) == NULL &&
		strncasecmp(this->encoded.ptr, other->encoded.ptr, this->encoded.len) == 0)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Default implementation of identification_t.matches.
 */
static id_match_t matches_binary(private_identification_t *this, 
						   private_identification_t *other)
{
	if (other->type == ID_ANY)
	{
		return ID_MATCH_ANY;
	}
	if (this->type == other->type && 
		chunk_equals(this->encoded, other->encoded))
	{
		return ID_MATCH_PERFECT;
	}
	return ID_MATCH_NONE;
}

/**
 * Special implementation of identification_t.matches for ID_RFC822_ADDR/ID_FQDN.
 * Checks for a wildcard in other-string, and compares it against this-string.
 */
static id_match_t matches_string(private_identification_t *this,
						   private_identification_t *other)
{
	u_int len = other->encoded.len;
	
	if (other->type == ID_ANY)
	{
		return ID_MATCH_ANY;
	}
	if (this->type != other->type)
	{
		return ID_MATCH_NONE;
	}
	/* try a equals check first */
	if (equals_strcasecmp(this, other))
	{
		return ID_MATCH_PERFECT;
	}
	if (len == 0 || this->encoded.len < len)
	{
		return ID_MATCH_NONE;
	}

	/* check for single wildcard at the head of the string */
	if (*other->encoded.ptr == '*')
	{
		/* single asterisk matches any string */
		if (len-- == 1)
		{	/* not better than ID_ANY */
			return ID_MATCH_ANY;
		}
		if (strncasecmp(this->encoded.ptr + this->encoded.len - len, 
						other->encoded.ptr + 1, len) == 0)
		{
			return ID_MATCH_ONE_WILDCARD;
		}
	}
	return ID_MATCH_NONE;
}

/**
 * Special implementation of identification_t.matches for ID_ANY.
 * ANY matches only another ANY, but nothing other
 */
static id_match_t matches_any(private_identification_t *this,
							  private_identification_t *other)
{
	if (other->type == ID_ANY)
	{
		return ID_MATCH_ANY;
	}
	return ID_MATCH_NONE;
}

/**
 * Special implementation of identification_t.matches for ID_DER_ASN1_DN
 */
static id_match_t matches_dn(private_identification_t *this,
							 private_identification_t *other)
{
	int wc;

	if (other->type == ID_ANY)
	{
		return ID_MATCH_ANY;
	}
	
	if (this->type == other->type)
	{
		if (match_dn(this->encoded, other->encoded, &wc))
		{
			return ID_MATCH_PERFECT - wc;
		}
	}
	return ID_MATCH_NONE;
}

/**
 * Described in header.
 */
int identification_printf_hook(char *dst, size_t len, printf_hook_spec_t *spec,
							   const void *const *args)
{
	private_identification_t *this = *((private_identification_t**)(args[0]));
	char buf[BUF_LEN];
	chunk_t proper, buf_chunk = chunk_from_buf(buf);
	
	if (this == NULL)
	{
		return print_in_hook(dst, len, "%*s", spec->width, "(null)");
	}
	
	switch (this->type)
	{
		case ID_ANY:
			snprintf(buf, sizeof(buf), "%%any");
			break;
		case ID_IPV4_ADDR:
			if (this->encoded.len < sizeof(struct in_addr) ||
				inet_ntop(AF_INET, this->encoded.ptr, buf, sizeof(buf)) == NULL)
			{
				snprintf(buf, sizeof(buf), "(invalid ID_IPV4_ADDR)");
			}
			break;
		case ID_IPV6_ADDR:
			if (this->encoded.len < sizeof(struct in6_addr) ||
				inet_ntop(AF_INET6, this->encoded.ptr, buf, INET6_ADDRSTRLEN) == NULL)
			{
				snprintf(buf, sizeof(buf), "(invalid ID_IPV6_ADDR)");
			}
			break;
		case ID_FQDN:
		case ID_RFC822_ADDR:
		case ID_DER_ASN1_GN_URI:
		case ID_IETF_ATTR_STRING:
			sanitize_chunk(this->encoded, &proper);
			snprintf(buf, sizeof(buf), "%.*s", proper.len, proper.ptr);
			chunk_free(&proper);
			break;
		case ID_DER_ASN1_DN:
			if (!dntoa(this->encoded, &buf_chunk))
			{
				snprintf(buf, sizeof(buf), "(invalid ID_DER_ASN1_DN)");
			}
			break;
		case ID_DER_ASN1_GN:
			snprintf(buf, sizeof(buf), "(ASN.1 general Name");
			break;
		case ID_KEY_ID:
			if (sanitize_chunk(this->encoded, &proper))
			{	/* fully printable, use ascii version */
				snprintf(buf, sizeof(buf), "%.*s", proper.len, proper.ptr);
			}
			else
			{	/* not printable, hex dump */
				snprintf(buf, sizeof(buf), "%#B", &this->encoded);
			}
			chunk_free(&proper);
			break;
		case ID_PUBKEY_INFO_SHA1:
		case ID_PUBKEY_SHA1:
		case ID_CERT_DER_SHA1:
			snprintf(buf, sizeof(buf), "%#B", &this->encoded);
			break;
		default:
			snprintf(buf, sizeof(buf), "(unknown ID type: %d)", this->type);
			break;
	}
	if (spec->minus)
	{
		return print_in_hook(dst, len, "%-*s", spec->width, buf);
	}
	return print_in_hook(dst, len, "%*s", spec->width, buf);
}

/**
 * Implementation of identification_t.clone.
 */
static identification_t *clone_(private_identification_t *this)
{
	private_identification_t *clone = identification_create();
	
	clone->type = this->type;
	if (this->encoded.len)
	{
		clone->encoded = chunk_clone(this->encoded);
	}
	clone->public.equals = this->public.equals;
	clone->public.matches = this->public.matches;
	
	return &clone->public;
}

/**
 * Implementation of identification_t.destroy.
 */
static void destroy(private_identification_t *this)
{
	chunk_free(&this->encoded);
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
	this->public.contains_wildcards = (bool (*) (identification_t *this))contains_wildcards;
	this->public.clone = (identification_t* (*) (identification_t*))clone_;
	this->public.destroy = (void (*) (identification_t*))destroy;
	/* we use these as defaults, the may be overloaded for special ID types */
	this->public.equals = (bool (*) (identification_t*,identification_t*))equals_binary;
	this->public.matches = (id_match_t (*) (identification_t*,identification_t*))matches_binary;
	
	this->encoded = chunk_empty;
	
	return this;
}

/*
 * Described in header.
 */
identification_t *identification_create_from_string(char *string)
{
	private_identification_t *this = identification_create();

	if (string == NULL)
	{
		string = "%any";
	}
	if (strchr(string, '=') != NULL)
	{
		/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN.
		 * convert from LDAP style or openssl x509 -subject style to ASN.1 DN
		 */
		if (atodn(string, &this->encoded) != SUCCESS)
		{
			this->type = ID_KEY_ID;
			this->encoded = chunk_clone(chunk_create(string, strlen(string)));
			return &this->public;
		}
		this->type = ID_DER_ASN1_DN;
		this->public.equals = (bool (*) (identification_t*,identification_t*))equals_dn;
		this->public.matches = (id_match_t (*) (identification_t*,identification_t*))matches_dn;
		return &this->public;
	}
	else if (strchr(string, '@') == NULL)
	{
		if (streq(string, "%any")
		||  streq(string, "%any6")
		||	streq(string, "0.0.0.0")
		||	streq(string, "*")
		||	streq(string, "::")
		||	streq(string, "0::0"))
		{
			/* any ID will be accepted */
			this->type = ID_ANY;
			this->public.matches = (id_match_t (*)
					(identification_t*,identification_t*))matches_any;
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
					/* not IPv4, mostly FQDN */
					this->type = ID_FQDN;
					this->encoded.ptr = strdup(string);
					this->encoded.len = strlen(string);
					this->public.matches = (id_match_t (*) 
						(identification_t*,identification_t*))matches_string;
					this->public.equals = (bool (*)
						(identification_t*,identification_t*))equals_strcasecmp;
					return &this->public;
				}
				this->encoded = chunk_clone(chunk);
				this->type = ID_IPV4_ADDR;
				return &this->public;
			}
			else
			{
				/* try IPv6 */
				struct in6_addr address;
				chunk_t chunk = {(void*)&address, sizeof(address)};
				
				if (inet_pton(AF_INET6, string, &address) <= 0)
				{
					this->type = ID_KEY_ID;
					this->encoded = chunk_clone(chunk_create(string,
															 strlen(string)));
					return &this->public;
				}
				this->encoded = chunk_clone(chunk);
				this->type = ID_IPV6_ADDR;
				return &this->public;
			}
		}
	}
	else
	{
		if (*string == '@')
		{
			if (*(string + 1) == '#')
			{
				string += 2;
				this->type = ID_KEY_ID;
				this->encoded = chunk_from_hex(
									chunk_create(string, strlen(string)), NULL);
				return &this->public;
			}
			else
			{
				this->type = ID_FQDN;
				this->encoded.ptr = strdup(string + 1);
				this->encoded.len = strlen(string + 1);
				this->public.matches = (id_match_t (*) 
						(identification_t*,identification_t*))matches_string;
				this->public.equals = (bool (*)
							(identification_t*,identification_t*))equals_strcasecmp;
				return &this->public;
			}
		}
		else
		{
			this->type = ID_RFC822_ADDR;
			this->encoded.ptr = strdup(string);
			this->encoded.len = strlen(string);
			this->public.matches = (id_match_t (*) 
					(identification_t*,identification_t*))matches_string;
			this->public.equals = (bool (*)
						(identification_t*,identification_t*))equals_strcasecmp;
			return &this->public;
		}
	}
}

/*
 * Described in header.
 */
identification_t *identification_create_from_encoding(id_type_t type, chunk_t encoded)
{
	private_identification_t *this = identification_create();

	this->type = type;
	switch (type)
	{
		case ID_ANY:
			this->public.matches = (id_match_t (*)
					(identification_t*,identification_t*))matches_any;
			break;
		case ID_FQDN:
		case ID_RFC822_ADDR:
			this->public.matches = (id_match_t (*)
					(identification_t*,identification_t*))matches_string;
			this->public.equals = (bool (*)
						(identification_t*,identification_t*))equals_strcasecmp;
			break;
		case ID_DER_ASN1_DN:
			this->public.equals = (bool (*)
					(identification_t*,identification_t*))equals_dn;
			this->public.matches = (id_match_t (*)
					(identification_t*,identification_t*))matches_dn;
			break;
		case ID_IPV4_ADDR:
		case ID_IPV6_ADDR:
		case ID_DER_ASN1_GN:
		case ID_KEY_ID:
		case ID_DER_ASN1_GN_URI:
		case ID_PUBKEY_INFO_SHA1:
		case ID_PUBKEY_SHA1:
		case ID_CERT_DER_SHA1:
		case ID_IETF_ATTR_STRING:
		default:
			break;
	}
	
	/* apply encoded chunk */
	if (type != ID_ANY)
	{
		this->encoded = chunk_clone(encoded);
	}
	return &(this->public);
}

