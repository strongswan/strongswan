/*
 * Copyright (C) 2009 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
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

/**
 * Enumerator over RDNs
 */
typedef struct {
	/* implements enumerator interface */
	enumerator_t public;
	/* RDNs left to parse */
	chunk_t left;
} rdn_enumerator_t;

/**
 * Implementation of rdn_enumerator_t.enumerate
 */
static bool rdn_enumerate(rdn_enumerator_t *this, chunk_t *oid,
						  u_char *type, chunk_t *data)
{
	chunk_t rdn;
	
	/* a RDN is a SET of attribute-values, each is a SEQUENCE ... */
	if (asn1_unwrap(&this->left, &rdn) == ASN1_SET &&
		asn1_unwrap(&rdn, &rdn) == ASN1_SEQUENCE)
	{
		/* ... of an OID */
		if (asn1_unwrap(&rdn, oid) == ASN1_OID)
		{
			/* and a specific string type */
			*type = asn1_unwrap(&rdn, data);
			if (*type != ASN1_INVALID)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Create an enumerator over all RDNs (oid, string type, data) of a DN
 */
static enumerator_t* create_rdn_enumerator(chunk_t dn)
{
	rdn_enumerator_t *e = malloc_thing(rdn_enumerator_t);
	
	e->public.enumerate = (void*)rdn_enumerate;
	e->public.destroy = (void*)free;
	
	/* a DN is a sequence of RDNs */
	if (asn1_unwrap(&dn, &e->left) == ASN1_SEQUENCE)
	{
		return &e->public;
	}
	free(e);
	return enumerator_create_empty();
}

/**
 * Part enumerator over RDNs
 */
typedef struct {
	/* implements enumerator interface */
	enumerator_t public;
	/* inner RDN enumerator */
	enumerator_t *inner;
} rdn_part_enumerator_t;

/**
 * Implementation of rdn_part_enumerator_t.enumerate().
 */
static bool rdn_part_enumerate(rdn_part_enumerator_t *this,
							   id_part_t *type, chunk_t *data)
{
	int i, known_oid, strtype;
	chunk_t oid, inner_data;
	static const struct {
		int oid;
		id_part_t type;
	} oid2part[] = {
		{OID_COMMON_NAME,		ID_PART_RDN_CN},
		{OID_SURNAME,			ID_PART_RDN_S},
		{OID_SERIAL_NUMBER,		ID_PART_RDN_SN},
		{OID_COUNTRY,			ID_PART_RDN_C},
		{OID_LOCALITY,			ID_PART_RDN_L},
		{OID_STATE_OR_PROVINCE,	ID_PART_RDN_ST},
		{OID_ORGANIZATION,		ID_PART_RDN_O},
		{OID_ORGANIZATION_UNIT,	ID_PART_RDN_OU},
		{OID_TITLE,				ID_PART_RDN_T},
		{OID_DESCRIPTION,		ID_PART_RDN_D},
		{OID_NAME,				ID_PART_RDN_N},
		{OID_GIVEN_NAME,		ID_PART_RDN_G},
		{OID_INITIALS,			ID_PART_RDN_I},
		{OID_UNIQUE_IDENTIFIER,	ID_PART_RDN_ID},
		{OID_EMAIL_ADDRESS,		ID_PART_RDN_E},
		{OID_EMPLOYEE_NUMBER,	ID_PART_RDN_EN},
	};
	
	while (this->inner->enumerate(this->inner, &oid, &strtype, &inner_data))
	{
		known_oid = asn1_known_oid(oid);
		for (i = 0; i < countof(oid2part); i++)
		{
			if (oid2part[i].oid == known_oid)
			{
				*type = oid2part[i].type;
				*data = inner_data;
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Implementation of rdn_part_enumerator_t.destroy().
 */
static void rdn_part_enumerator_destroy(rdn_part_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of identification_t.create_part_enumerator
 */
static enumerator_t* create_part_enumerator(private_identification_t *this)
{
	switch (this->type)
	{
		case ID_DER_ASN1_DN:
		{
			rdn_part_enumerator_t *e = malloc_thing(rdn_part_enumerator_t);
			
			e->inner = create_rdn_enumerator(this->encoded);
			e->public.enumerate = (void*)rdn_part_enumerate;
			e->public.destroy = (void*)rdn_part_enumerator_destroy;
			
			return &e->public;
		}
		case ID_RFC822_ADDR:
			/* TODO */
		case ID_FQDN:
			/* TODO */
		default:
			return enumerator_create_empty();
	}
}

/**
 * Print a DN with all its RDN in a buffer to present it to the user
 */
static void dntoa(chunk_t dn, char *buf, size_t len)
{
	enumerator_t *e;
	chunk_t oid_data, data;
	u_char type;
	int oid, written;
	bool finished = FALSE;
	
	e = create_rdn_enumerator(dn);
	while (e->enumerate(e, &oid_data, &type, &data))
	{
		oid = asn1_known_oid(oid_data);
		
		if (oid == OID_UNKNOWN)
		{
			written = snprintf(buf, len, "%#B=", &oid_data);
		}
		else
		{
			written = snprintf(buf, len,"%s=", oid_names[oid].name);
		}
		buf += written;
		len -= written;
		
		if (chunk_printable(data, NULL, '?'))
		{
			written = snprintf(buf, len, "%.*s", data.len, data.ptr);
		}
		else
		{
			written = snprintf(buf, len, "%#B", &data);
		}
		buf += written;
		len -= written;
		
		if (data.ptr + data.len != dn.ptr + dn.len)
		{
			written = snprintf(buf, len, " ");
			buf += written;
			len -= written;
		}
		else
		{
			finished = TRUE;
			break;
		}
	}
	if (!finished)
	{
		snprintf(buf, len, "(invalid ID_DER_ASN1_DN)");
	}
	e->destroy(e);
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
						
						rdn_oid = asn1_build_known_oid(x501rdns[i].oid);
						if (rdn_oid.len)
						{
							rdns[rdn_count] = 
									asn1_wrap(ASN1_SET, "m",
										asn1_wrap(ASN1_SEQUENCE, "mm",
											rdn_oid,
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
	enumerator_t *enumerator;
	bool contains = FALSE;
	id_part_t type;
	chunk_t data;
	
	enumerator = create_part_enumerator(this);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (data.len == 1 && data.ptr[0] == '*')
		{
			contains = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return contains;
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
 * Compare to DNs, for equality if wc == NULL, for match otherwise
 */
static bool compare_dn(chunk_t t_dn, chunk_t o_dn, int *wc)
{
	enumerator_t *t, *o;
	chunk_t t_oid, o_oid, t_data, o_data;
	u_char t_type, o_type;
	bool t_next, o_next, finished = FALSE;
	
	if (wc)
	{
		*wc = 0;
	}
	else
	{
		if (t_dn.len != o_dn.len)
		{
			return FALSE;
		}
	}
	/* try a binary compare */
	if (memeq(t_dn.ptr, o_dn.ptr, t_dn.len))
	{
		return TRUE;
	}
	
	t = create_rdn_enumerator(t_dn);
	o = create_rdn_enumerator(o_dn);
	while (TRUE)
	{
		t_next = t->enumerate(t, &t_oid, &t_type, &t_data);
		o_next = o->enumerate(o, &o_oid, &o_type, &o_data);
		
		if (!o_next && !t_next)
		{
			break;
		}
		finished = FALSE;
		if (o_next != t_next)
		{
			break;
		}
		if (!chunk_equals(t_oid, o_oid))
		{
			break;
		}
		if (wc && o_data.len == 1 && o_data.ptr[0] == '*')
		{
			(*wc)++;
		}
		else
		{
			if (t_data.len != o_data.len)
			{
				break;
			}
			if (t_type == o_type &&
				(t_type == ASN1_PRINTABLESTRING ||
				 (t_type == ASN1_IA5STRING &&
				  (asn1_known_oid(t_oid) == OID_PKCS9_EMAIL ||
				   asn1_known_oid(t_oid) == OID_EMAIL_ADDRESS))))
			{	/* ignore case for printableStrings and email RDNs */
				if (strncasecmp(t_data.ptr, o_data.ptr, t_data.len) != 0)
				{
					break;
				}
			}
			else
			{	/* respect case and length for everything else */
				if (!memeq(t_data.ptr, o_data.ptr, t_data.len))
				{
					break;
				}
			}
		}
		/* the enumerator returns FALSE on parse error, we are finished
		 * if we have reached the end of the DN only */
		if ((t_data.ptr + t_data.len == t_dn.ptr + t_dn.len) &&
			(o_data.ptr + o_data.len == o_dn.ptr + o_dn.len))
		{
			finished = TRUE;
		}
	}
	t->destroy(t);
	o->destroy(o);
	return finished;
}

/**
 * Special implementation of identification_t.equals for ID_DER_ASN1_DN.
 */
static bool equals_dn(private_identification_t *this,
					  private_identification_t *other)
{
	return compare_dn(this->encoded, other->encoded, NULL);
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
		if (compare_dn(this->encoded, other->encoded, &wc))
		{
			wc = min(wc, ID_MATCH_ONE_WILDCARD - ID_MATCH_MAX_WILDCARDS);
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
	chunk_t proper;
	char buf[512];
	
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
			chunk_printable(this->encoded, &proper, '?');
			snprintf(buf, sizeof(buf), "%.*s", proper.len, proper.ptr);
			chunk_free(&proper);
			break;
		case ID_DER_ASN1_DN:
			dntoa(this->encoded, buf, sizeof(buf));
			break;
		case ID_DER_ASN1_GN:
			snprintf(buf, sizeof(buf), "(ASN.1 general Name");
			break;
		case ID_KEY_ID:
			if (chunk_printable(this->encoded, NULL, '?'))
			{	/* fully printable, use ascii version */
				snprintf(buf, sizeof(buf), "%.*s",
						 this->encoded.len, this->encoded.ptr);
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
	private_identification_t *clone = malloc_thing(private_identification_t);
	
	memcpy(clone, this, sizeof(private_identification_t));
	if (this->encoded.len)
	{
		clone->encoded = chunk_clone(this->encoded);
	}
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
	this->public.create_part_enumerator = (enumerator_t*(*)(identification_t*))create_part_enumerator;
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

