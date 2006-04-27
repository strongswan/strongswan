/**
 * @file identification.c
 * 
 * @brief Implementation of identification_t. 
 * 
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

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "identification.h"

#include <asn1/asn1.h>

/** 
 * String mappings for id_type_t.
 */
mapping_t id_type_m[] = {
	{ID_IPV4_ADDR, "ID_IPV4_ADDR"},
	{ID_FQDN, "ID_FQDN"},
	{ID_RFC822_ADDR, "ID_RFC822_ADDR"},
	{ID_IPV6_ADDR, "ID_IPV6_ADDR"},
	{ID_DER_ASN1_DN, "ID_DER_ASN1_DN"},
	{ID_DER_ASN1_GN, "ID_DER_ASN1_GN"},
	{ID_KEY_ID, "ID_KEY_ID"},
	{ID_ANY, "ID_ANY"},
	{MAPPING_END, NULL}
};


/**
 * X.501 acronyms for well known object identifiers (OIDs)
 */
static u_char oid_ND[]  = {
	0x02, 0x82, 0x06, 0x01, 
	0x0A, 0x07, 0x14
};
static u_char oid_UID[] = {
	0x09, 0x92, 0x26, 0x89, 0x93,
	0xF2, 0x2C, 0x64, 0x01, 0x01
};
static u_char oid_DC[]  = {
	0x09, 0x92, 0x26, 0x89, 0x93,
	0xF2, 0x2C, 0x64, 0x01, 0x19
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
	0x60, 0x86, 0x48, 0x01, 0x86,
	0xF8, 0x42, 0x03, 0x01, 0x03
};
static u_char oid_E[] = {
	0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x09, 0x01
};
static u_char oid_UN[]  = {
	0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x09, 0x02
};
static u_char oid_TCGID[] = {
	0x2B, 0x06, 0x01, 0x04, 0x01, 0x89,
	0x31, 0x01, 0x01, 0x02, 0x02, 0x4B
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
 * Different kinds of generalNames
 */
enum generalNames_t {
	GN_OTHER_NAME =		0,
	GN_RFC822_NAME =	1,
	GN_DNS_NAME =		2,
	GN_X400_ADDRESS =	3,
	GN_DIRECTORY_NAME =	4,
	GN_EDI_PARTY_NAME = 5,
	GN_URI =			6,
	GN_IP_ADDRESS =		7,
	GN_REGISTERED_ID =	8,
};

/**
 * ASN.1 definition of generalName 
 */
static const asn1Object_t generalNameObjects[] = {
	{ 0,   "otherName",		ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_BODY	}, /*  0 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /*  1 */
	{ 0,   "rfc822Name",	ASN1_CONTEXT_S_1,  ASN1_OPT|ASN1_BODY	}, /*  2 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END 			}, /*  3 */
	{ 0,   "dnsName",		ASN1_CONTEXT_S_2,  ASN1_OPT|ASN1_BODY	}, /*  4 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /*  5 */
	{ 0,   "x400Address",	ASN1_CONTEXT_S_3,  ASN1_OPT|ASN1_BODY	}, /*  6 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /*  7 */
	{ 0,   "directoryName",	ASN1_CONTEXT_C_4,  ASN1_OPT|ASN1_BODY	}, /*  8 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /*  9 */
	{ 0,   "ediPartyName",	ASN1_CONTEXT_C_5,  ASN1_OPT|ASN1_BODY	}, /* 10 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /* 11 */
	{ 0,   "URI",			ASN1_CONTEXT_S_6,  ASN1_OPT|ASN1_BODY	}, /* 12 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /* 13 */
	{ 0,   "ipAddress",		ASN1_CONTEXT_S_7,  ASN1_OPT|ASN1_BODY	}, /* 14 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}, /* 15 */
	{ 0,   "registeredID",	ASN1_CONTEXT_S_8,  ASN1_OPT|ASN1_BODY	}, /* 16 */
	{ 0,   "end choice",	ASN1_EOC,          ASN1_END				}  /* 17 */
};
#define GN_OBJ_OTHER_NAME	 	 0
#define GN_OBJ_RFC822_NAME	 	 2
#define GN_OBJ_DNS_NAME		 	 4
#define GN_OBJ_X400_ADDRESS	 	 6
#define GN_OBJ_DIRECTORY_NAME	 8
#define GN_OBJ_EDI_PARTY_NAME	10
#define GN_OBJ_URI				12
#define GN_OBJ_IP_ADDRESS		14
#define GN_OBJ_REGISTERED_ID	16
#define GN_OBJ_ROOF				18

/**
 * ASN.1 definition of otherName 
 */
static const asn1Object_t otherNameObjects[] = {
	{0, "type-id",	ASN1_OID,			ASN1_BODY	}, /*  0 */
	{0, "value",	ASN1_CONTEXT_C_0,	ASN1_BODY	}  /*  1 */
};
#define ON_OBJ_ID_TYPE		0
#define ON_OBJ_VALUE		1
#define ON_OBJ_ROOF			2

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

static private_identification_t *identification_create();


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
	for (i=0; i < bin.len; i++)
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
	{/* a parsing error has occured */
		return status;
	}

	while (next)
	{
		status = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

		if (status != SUCCESS)
		{/* a parsing error has occured */
			return status;
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
	{
		return FALSE;
	}
	/* try a binary comparison first */
	if (memcmp(a.ptr, b.ptr, b.len) == 0)
	{
		return TRUE;
	}
 
	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != SUCCESS ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != SUCCESS)
	{
		return FALSE;
	}

	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != SUCCESS ||  
			get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != SUCCESS)
		{
			return FALSE;
		}
		/* OIDs must agree */
		if (oid_a.len != oid_b.len || memcmp(oid_a.ptr, oid_b.ptr, oid_b.len) != 0)
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
				  (type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
		{
			if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
			{
				return FALSE;
			}
		}
		else
		{
			if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
			{
				return FALSE;
			}
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
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != SUCCESS ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != SUCCESS)
	{
		return FALSE;
	}
	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != SUCCESS ||
			get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != SUCCESS)
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
			(type_a == ASN1_IA5STRING && known_oid(oid_a) == OID_PKCS9_EMAIL)))
		{
			if (strncasecmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
			{
				return FALSE;
			}
		}
		else
		{
			if (strncmp(value_a.ptr, value_b.ptr, value_b.len) != 0)
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
	return TRUE;
}

/**
 * get string representation of a general name
 * TODO: Add support for gn types
 */
static char *gntoa(chunk_t blob)
{
	asn1_ctx_t ctx;
	chunk_t object;
	int objectID = 0;
	u_int level;
	char buf[128];

	asn1_init(&ctx, blob, 0, FALSE);

	while (objectID < GN_OBJ_ROOF)
	{
		if (!extract_object(generalNameObjects, &objectID, &object, &level, &ctx))
		{
			return NULL;
		}
		switch (objectID)
		{
			case GN_OBJ_RFC822_NAME:
			case GN_OBJ_DNS_NAME:
			case GN_OBJ_URI:
				snprintf(buf, sizeof(buf), "%.*s", object.len, object.ptr);
				return strdup(buf);
			case GN_OBJ_IP_ADDRESS:
				if (object.len == 4 &&
					inet_ntop(AF_INET, object.ptr, buf, sizeof(buf)))
				{
					return strdup(buf);
				}
				return NULL;
				break;
			case GN_OBJ_OTHER_NAME:
				return strdup("(other name)");
			case GN_OBJ_X400_ADDRESS:
				return strdup("(X400 Address)");
			case GN_OBJ_EDI_PARTY_NAME:
				return strdup("(EDI party name)");
			case GN_OBJ_REGISTERED_ID:
				return strdup("(registered ID)");
			case GN_OBJ_DIRECTORY_NAME:
				return strdup("(directory name)");
			default:
				break;
		}
		objectID++;
	}
	return NULL;
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
	
	char *wrap_mode;
	chunk_t oid  = CHUNK_INITIALIZER;
	chunk_t name = CHUNK_INITIALIZER;
	chunk_t names[25]; /* max to 25 rdns */
	int name_count = 0;
	int whitespace = 0;
	int pos = 0;
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
					for (pos = 0; pos < X501_RDN_ROOF; pos++)
					{
						if (strlen(x501rdns[pos].name) == oid.len &&
											  strncasecmp(x501rdns[pos].name, oid.ptr, oid.len) == 0)
						{
							break; /* found a valid OID */
						}
					}
					if (pos == X501_RDN_ROOF)
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
					{
						whitespace++;
					}
					else
					{
						whitespace = 0;
					}
				}
				else
				{
					name.len -= whitespace;
					rdn_type = (x501rdns[pos].type == ASN1_PRINTABLESTRING
							&& !is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
					
					if (name_count < 25)
					{
						names[name_count++] = 
								asn1_wrap(ASN1_SET, "m",
										  asn1_wrap(ASN1_SEQUENCE, "mm",
												  asn1_wrap(ASN1_OID, "c", x501rdns[pos].oid),
												  asn1_wrap(rdn_type, "c", name)
												   )
										 );
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
	wrap_mode = alloca(26);
	memset(wrap_mode, 0, 26);
	memset(wrap_mode, 'm', name_count);
	*dn = asn1_wrap(ASN1_SEQUENCE, wrap_mode, 
					names[0], names[1], names[2], names[3], names[4], 
					names[5], names[6], names[7], names[8], names[9],
					names[10], names[11], names[12], names[13], names[14], 
					names[15], names[16], names[17], names[18], names[19], 
					names[20], names[21], names[22], names[23], names[24]);
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
	if (this->type == ID_ANY ||
		memchr(this->encoded.ptr, '*', this->encoded.len) != NULL)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Default implementation of identification_t.equals and identification_t.belongs_to.
 * compares encoded chunk for equality.
 */
static bool equals_binary(private_identification_t *this,private_identification_t *other)
{
	if (this->type == other->type)
	{
		if (this->encoded.len == other->encoded.len &&
			memcmp(this->encoded.ptr, other->encoded.ptr, this->encoded.len) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Special implementation of identification_t.equals for ID_DER_ASN1_DN
 */
static bool equals_dn(private_identification_t *this, private_identification_t *other)
{
	return same_dn(this->encoded, other->encoded);
}

/**
 * Special implementation of identification_t.belongs_to for ID_RFC822_ADDR/ID_FQDN.
 * checks for a wildcard in other-string, and compares it against this-string.
 */
static bool belongs_to_wc_string(private_identification_t *this, private_identification_t *other)
{
	char *this_str, *other_str, *pos;
	
	if (other->type == ID_ANY)
	{
		return TRUE;
	}
	
	if (this->type == other->type)
	{
		/* try a binary comparison first */
		if (equals_binary(this, other))
		{
			return TRUE;
		}
	}
	if (other->encoded.len > 0 &&
		   *(other->encoded.ptr) == '*')
	{
		if (other->encoded.len == 1)
		{
			/* other contains just a wildcard, and therefore matches anything */
			return TRUE;
		}
		/* We strdup chunks, since they are NOT null-terminated */
		this_str = strndupa(this->encoded.ptr, this->encoded.len);
		other_str = strndupa(other->encoded.ptr + 1, other->encoded.len - 1);
		pos = strstr(this_str, other_str);
		if (pos != NULL)
		{
			/* ok, other is contained in this, but there may be more characters, so check it */
			if (strlen(pos) == strlen(other_str))
			{
				return TRUE;
			}
		}
	}
	
	return FALSE;
}

/**
 * Special implementation of identification_t.belongs_to for ID_ANY.
 * ANY matches only another ANY, but nothing other
 */
static bool belongs_to_any(private_identification_t *this, private_identification_t *other)
{	
	if (other->type == ID_ANY)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Special implementation of identification_t.belongs_to for ID_DER_ASN1_DN.
 * ANY matches any, even ANY, thats why its there...
 */
static bool belongs_to_dn(private_identification_t *this, private_identification_t *other)
{
	int wildcards;
	
	if (other->type == ID_ANY)
	{
		return TRUE;
	}
	
	if (this->type == other->type)
	{
		return match_dn(this->encoded, other->encoded, &wildcards);
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
static private_identification_t *identification_create()
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
	this->public.belongs_to = (bool (*) (identification_t*,identification_t*))equals_binary;
	
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
	
	if (strchr(string, '=') != NULL)
	{
		/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN.
		 * convert from LDAP style or openssl x509 -subject style to ASN.1 DN
		 * discard optional @ character in front of DN
		 */
		if (atodn((*string == '@') ? string + 1 : string, &this->encoded) != SUCCESS)
		{
			free(this);
			return NULL;
		}
		this->string = strdup(string);
		this->type = ID_DER_ASN1_DN;
		this->public.equals = (bool (*) (identification_t*,identification_t*))equals_dn;
		this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_dn;
		return &this->public;
	}
	else if (strchr(string, '@') == NULL)
	{
		if (strcmp(string, "%any") == 0 ||
			strcmp(string, "0.0.0.0") == 0 ||
			strcmp(string, "*") == 0 ||
			strcmp(string, "::") == 0||
			strcmp(string, "0::0") == 0)
		{
			/* any ID will be accepted */
			this->type = ID_ANY;
			this->string = strdup("%any");
			this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_any;
			return &this->public;
		}
		else
		{
			/* TODO: Pluto resolve domainnames without '@' to IPv4/6 address. Is this really needed? */
			
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
				/* TODO: Pluto handles '#' as hex encoded ASN1/KEY ID. Do we need this, too? */
				free(this);
				return NULL;
			}
			else
			{
				this->type = ID_FQDN;
				this->string = strdup(string + 1); /* discard @ */
				this->encoded.ptr = strdup(string + 1);
				this->encoded.len = strlen(string + 1);
				this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_wc_string;
				return &(this->public);
			}
		}
		else
		{
			this->type = ID_RFC822_ADDR;
			this->string = strdup(string);
			this->encoded.ptr = strdup(string);
			this->encoded.len = strlen(string);
			this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_wc_string;
			return &(this->public);
		}
	}
}

/*
 * Described in header.
 */
identification_t *identification_create_from_encoding(id_type_t type, chunk_t encoded)
{
	private_identification_t *this = identification_create();
	char buf[256];
	chunk_t buf_chunk = chunk_from_buf(buf);
	char *pos;
	
	this->type = type;
	switch (type)
	{
		case ID_ANY:
			this->string = strdup("%any");
			this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_any;
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
			this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_wc_string;
			break;
		case ID_RFC822_ADDR:
			snprintf(buf, sizeof(buf), "%.*s", encoded.len, encoded.ptr);
			this->string = strdup(buf);
			this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_wc_string;
			break;
		case ID_DER_ASN1_DN:
			snprintf(buf, sizeof(buf), "%.*s", encoded.len, encoded.ptr);
			/* TODO: whats returned on failure */
			dntoa(encoded, &buf_chunk);
			this->string = strdup(buf);
			this->public.equals = (bool (*) (identification_t*,identification_t*))equals_dn;
			this->public.belongs_to = (bool (*) (identification_t*,identification_t*))belongs_to_dn;
			break;
		case ID_DER_ASN1_GN:
			this->string = gntoa(encoded);
			break;
		case ID_KEY_ID:
			this->string = strdup("(unparsed KEY_ID)");
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
