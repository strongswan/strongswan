/* Support of X.509 certificates
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <freeswan.h>

#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/hashers/hasher.h>
#include <utils/enumerator.h>
#include <utils/identification.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certs.h"
#include "keys.h"
#include "whack.h"
#include "fetch.h"
#include "ocsp.h"

/**
 * Chained lists of X.509 end certificates
 */
static x509cert_t *x509certs     = NULL;

/**
 * ASN.1 definition of a authorityKeyIdentifier extension
 */
static const asn1Object_t authKeyIdentifierObjects[] = {
	{ 0, "authorityKeyIdentifier",		ASN1_SEQUENCE,	  ASN1_NONE          }, /* 0 */
	{ 1,   "keyIdentifier",				ASN1_CONTEXT_S_0, ASN1_OPT|ASN1_BODY }, /* 1 */
	{ 1,   "end opt",					ASN1_EOC,		  ASN1_END           }, /* 2 */
	{ 1,   "authorityCertIssuer",		ASN1_CONTEXT_C_1, ASN1_OPT|ASN1_OBJ  }, /* 3 */
	{ 1,   "end opt",					ASN1_EOC,		  ASN1_END           }, /* 4 */
	{ 1,   "authorityCertSerialNumber",	ASN1_CONTEXT_S_2, ASN1_OPT|ASN1_BODY }, /* 5 */
	{ 1,   "end opt",					ASN1_EOC,		  ASN1_END           }, /* 6 */
	{ 0, "exit",						ASN1_EOC,		  ASN1_EXIT          }
};
#define AUTH_KEY_ID_KEY_ID			1
#define AUTH_KEY_ID_CERT_ISSUER		3
#define AUTH_KEY_ID_CERT_SERIAL		5

/**
 * ASN.1 definition of generalNames
 */
static const asn1Object_t generalNamesObjects[] = {
	{ 0, "generalNames",	ASN1_SEQUENCE,	ASN1_LOOP }, /* 0 */
	{ 1,   "generalName",	ASN1_EOC,		ASN1_RAW  }, /* 1 */
	{ 0, "end loop",		ASN1_EOC,		ASN1_END  }, /* 2 */
	{ 0, "exit",			ASN1_EOC,		ASN1_EXIT }
};
#define GENERAL_NAMES_GN	1

/**
 * ASN.1 definition of generalName
 */
static const asn1Object_t generalNameObjects[] = {
	{ 0, "otherName",		ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_BODY	}, /*  0 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /*  1 */
	{ 0, "rfc822Name",		ASN1_CONTEXT_S_1,  ASN1_OPT|ASN1_BODY	}, /*  2 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END 			}, /*  3 */
	{ 0, "dnsName",			ASN1_CONTEXT_S_2,  ASN1_OPT|ASN1_BODY	}, /*  4 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /*  5 */
	{ 0, "x400Address",		ASN1_CONTEXT_S_3,  ASN1_OPT|ASN1_BODY	}, /*  6 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /*  7 */
	{ 0, "directoryName",	ASN1_CONTEXT_C_4,  ASN1_OPT|ASN1_BODY	}, /*  8 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /*  9 */
	{ 0, "ediPartyName",	ASN1_CONTEXT_C_5,  ASN1_OPT|ASN1_BODY	}, /* 10 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /* 11 */
	{ 0, "URI",				ASN1_CONTEXT_S_6,  ASN1_OPT|ASN1_BODY	}, /* 12 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /* 13 */
	{ 0, "ipAddress",		ASN1_CONTEXT_S_7,  ASN1_OPT|ASN1_BODY	}, /* 14 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /* 15 */
	{ 0, "registeredID",	ASN1_CONTEXT_S_8,  ASN1_OPT|ASN1_BODY	}, /* 16 */
	{ 0, "end choice",		ASN1_EOC,          ASN1_END				}, /* 17 */
	{ 0, "exit",			ASN1_EOC,          ASN1_EXIT			}
};
#define GN_OBJ_OTHER_NAME		 0
#define GN_OBJ_RFC822_NAME		 2
#define GN_OBJ_DNS_NAME			 4
#define GN_OBJ_X400_ADDRESS		 6
#define GN_OBJ_DIRECTORY_NAME	 8
#define GN_OBJ_EDI_PARTY_NAME	10
#define GN_OBJ_URI				12
#define GN_OBJ_IP_ADDRESS		14
#define GN_OBJ_REGISTERED_ID	16

/**
 * ASN.1 definition of otherName
 */
static const asn1Object_t otherNameObjects[] = {
	{0, "type-id",	ASN1_OID,			ASN1_BODY	}, /* 0 */
	{0, "value",	ASN1_CONTEXT_C_0,	ASN1_BODY	}, /* 1 */
	{0, "exit",		ASN1_EOC,			ASN1_EXIT	}
};
#define ON_OBJ_ID_TYPE		0
#define ON_OBJ_VALUE		1

const x509cert_t empty_x509cert = {
	  NULL        , /* cert */
	  NULL        , /* *next */
			0     , /* count */
	  FALSE         /* smartcard */
};

/* coding of X.501 distinguished name */

typedef struct {
	const u_char *name;
	chunk_t oid;
	u_char type;
} x501rdn_t;

/* X.501 acronyms for well known object identifiers (OIDs) */

static u_char oid_ND[]  = {0x02, 0x82, 0x06, 0x01,
						   0x0A, 0x07, 0x14};
static u_char oid_UID[] = {0x09, 0x92, 0x26, 0x89, 0x93,
						   0xF2, 0x2C, 0x64, 0x01, 0x01};
static u_char oid_DC[]  = {0x09, 0x92, 0x26, 0x89, 0x93,
						   0xF2, 0x2C, 0x64, 0x01, 0x19};
static u_char oid_CN[]  = {0x55, 0x04, 0x03};
static u_char oid_S[]   = {0x55, 0x04, 0x04};
static u_char oid_SN[]  = {0x55, 0x04, 0x05};
static u_char oid_C[]   = {0x55, 0x04, 0x06};
static u_char oid_L[]   = {0x55, 0x04, 0x07};
static u_char oid_ST[]  = {0x55, 0x04, 0x08};
static u_char oid_O[]   = {0x55, 0x04, 0x0A};
static u_char oid_OU[]  = {0x55, 0x04, 0x0B};
static u_char oid_T[]   = {0x55, 0x04, 0x0C};
static u_char oid_D[]   = {0x55, 0x04, 0x0D};
static u_char oid_N[]   = {0x55, 0x04, 0x29};
static u_char oid_G[]   = {0x55, 0x04, 0x2A};
static u_char oid_I[]   = {0x55, 0x04, 0x2B};
static u_char oid_ID[]  = {0x55, 0x04, 0x2D};
static u_char oid_EN[]  = {0x60, 0x86, 0x48, 0x01, 0x86,
						   0xF8, 0x42, 0x03, 0x01, 0x03};
static u_char oid_E[]   = {0x2A, 0x86, 0x48, 0x86, 0xF7,
						   0x0D, 0x01, 0x09, 0x01};
static u_char oid_UN[]  = {0x2A, 0x86, 0x48, 0x86, 0xF7,
						   0x0D, 0x01, 0x09, 0x02};
static u_char oid_TCGID[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x89,
							 0x31, 0x01, 0x01, 0x02, 0x02, 0x4B};

static const x501rdn_t x501rdns[] = {
  {"ND"              , {oid_ND,     7}, ASN1_PRINTABLESTRING},
  {"UID"             , {oid_UID,   10}, ASN1_PRINTABLESTRING},
  {"DC"              , {oid_DC,    10}, ASN1_PRINTABLESTRING},
  {"CN"              , {oid_CN,     3}, ASN1_PRINTABLESTRING},
  {"S"               , {oid_S,      3}, ASN1_PRINTABLESTRING},
  {"SN"              , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"serialNumber"    , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"C"               , {oid_C,      3}, ASN1_PRINTABLESTRING},
  {"L"               , {oid_L,      3}, ASN1_PRINTABLESTRING},
  {"ST"              , {oid_ST,     3}, ASN1_PRINTABLESTRING},
  {"O"               , {oid_O,      3}, ASN1_PRINTABLESTRING},
  {"OU"              , {oid_OU,     3}, ASN1_PRINTABLESTRING},
  {"T"               , {oid_T,      3}, ASN1_PRINTABLESTRING},
  {"D"               , {oid_D,      3}, ASN1_PRINTABLESTRING},
  {"N"               , {oid_N,      3}, ASN1_PRINTABLESTRING},
  {"G"               , {oid_G,      3}, ASN1_PRINTABLESTRING},
  {"I"               , {oid_I,      3}, ASN1_PRINTABLESTRING},
  {"ID"              , {oid_ID,     3}, ASN1_PRINTABLESTRING},
  {"EN"              , {oid_EN,    10}, ASN1_PRINTABLESTRING},
  {"employeeNumber"  , {oid_EN,    10}, ASN1_PRINTABLESTRING},
  {"E"               , {oid_E,      9}, ASN1_IA5STRING},
  {"Email"           , {oid_E,      9}, ASN1_IA5STRING},
  {"emailAddress"    , {oid_E,      9}, ASN1_IA5STRING},
  {"UN"              , {oid_UN,     9}, ASN1_IA5STRING},
  {"unstructuredName", {oid_UN,     9}, ASN1_IA5STRING},
  {"TCGID"           , {oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};

#define X501_RDN_ROOF   26

static void update_chunk(chunk_t *ch, int n)
{
	n = (n > -1 && n < (int)ch->len)? n : (int)ch->len-1;
	ch->ptr += n; ch->len -= n;
}

/**
 *  Pointer is set to the first RDN in a DN
 */
static err_t init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
	*rdn = chunk_empty;
	*attribute = chunk_empty;

	/* a DN is a SEQUENCE OF RDNs */

	if (*dn.ptr != ASN1_SEQUENCE)
	{
		return "DN is not a SEQUENCE";
	}

	rdn->len = asn1_length(&dn);

	if (rdn->len == ASN1_INVALID_LENGTH)
	{
		return "Invalid RDN length";
	}
	rdn->ptr = dn.ptr;

	/* are there any RDNs ? */
	*next = rdn->len > 0;

	return NULL;
}

/**
 *  Fetches the next RDN in a DN
 */
static err_t get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid,
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
			return "RDN is not a SET";
		}
		attribute->len = asn1_length(rdn);

		if (attribute->len == ASN1_INVALID_LENGTH)
		{
			return "Invalid attribute length";
		}
		attribute->ptr = rdn->ptr;

		/* advance to start of next RDN */
		rdn->ptr += attribute->len;
		rdn->len -= attribute->len;
	}

	/* an attributeTypeAndValue is a SEQUENCE */
	if (*attribute->ptr != ASN1_SEQUENCE)
	{
		return "attributeTypeAndValue is not a SEQUENCE";
	}

	/* extract the attribute body */
	body.len = asn1_length(attribute);

	if (body.len == ASN1_INVALID_LENGTH)
	{
		return "Invalid attribute body length";
	}
	body.ptr = attribute->ptr;

	/* advance to start of next attribute */
	attribute->ptr += body.len;
	attribute->len -= body.len;

	/* attribute type is an OID */
	if (*body.ptr != ASN1_OID)
	{
		return "attributeType is not an OID";
	}

	/* extract OID */
	oid->len = asn1_length(&body);

	if (oid->len == ASN1_INVALID_LENGTH)
	{
		return "Invalid attribute OID length";
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
		return "Invalid attribute string length";
	}
	value->ptr = body.ptr;

	/* are there any RDNs left? */
	*next = rdn->len > 0 || attribute->len > 0;

	return NULL;
}

/**
 *  Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t dn_parse(chunk_t dn, chunk_t *str)
{
	chunk_t rdn, oid, attribute, value;
	asn1_t type;
	int oid_code;
	bool next;
	bool first = TRUE;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh) /* a parsing error has occured */
	{
		return ugh;
	}

	while (next)
	{
		ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

		if (ugh) /* a parsing error has occured */
		{
			return ugh;
		}

		if (first)              /* first OID/value pair */
		{
			first = FALSE;
		}
		else                    /* separate OID/value pair by a comma */
		{
			update_chunk(str, snprintf(str->ptr,str->len,", "));
		}

		/* print OID */
		oid_code = asn1_known_oid(oid);
		if (oid_code == OID_UNKNOWN)    /* OID not found in list */
		{
			hex_str(oid, str);
		}
		else
		{
			update_chunk(str, snprintf(str->ptr,str->len,"%s",
							  oid_names[oid_code].name));
		}

		/* print value */
		update_chunk(str, snprintf(str->ptr,str->len,"=%.*s",
							  (int)value.len,value.ptr));
	}
	return NULL;
}

/**
 *  Count the number of wildcard RDNs in a distinguished name
 */
int dn_count_wildcards(chunk_t dn)
{
	chunk_t rdn, attribute, oid, value;
	asn1_t type;
	bool next;
	int wildcards = 0;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh) /* a parsing error has occured */
	{
		return -1;
	}

	while (next)
	{
		ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

		if (ugh) /* a parsing error has occured */
		{
			return -1;
		}
		if (value.len == 1 && *value.ptr == '*')
		{
			wildcards++; /* we have found a wildcard RDN */
		}
	}
	return wildcards;
}

/**
 * Prints a binary string in hexadecimal form
 */
void hex_str(chunk_t bin, chunk_t *str)
{
	u_int i;
	update_chunk(str, snprintf(str->ptr,str->len,"0x"));
	for (i=0; i < bin.len; i++)
		update_chunk(str, snprintf(str->ptr,str->len,"%02X",*bin.ptr++));
}


/** Converts a binary DER-encoded ASN.1 distinguished name
 *  into LDAP-style human-readable ASCII format
 */
int dntoa(char *dst, size_t dstlen, chunk_t dn)
{
	err_t ugh = NULL;
	chunk_t str;

	str.ptr = dst;
	str.len = dstlen;
	ugh = dn_parse(dn, &str);

	if (ugh) /* error, print DN as hex string */
	{
		DBG(DBG_PARSING,
			DBG_log("error in DN parsing: %s", ugh)
		)
		str.ptr = dst;
		str.len = dstlen;
		hex_str(dn, &str);
	}
	return (int)(dstlen - str.len);
}

/**
 * Codes ASN.1 lengths up to a size of 16'777'215 bytes
 */
static void code_asn1_length(size_t length, chunk_t *code)
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
 *  Converts an LDAP-style human-readable ASCII-encoded
 *  ASN.1 distinguished name into binary DER-encoded format
 */
err_t atodn(char *src, chunk_t *dn)
{
  /* finite state machine for atodn */

	typedef enum {
		SEARCH_OID =    0,
		READ_OID =      1,
		SEARCH_NAME =   2,
		READ_NAME =     3,
		UNKNOWN_OID =   4
	} state_t;

	u_char oid_len_buf[3];
	u_char name_len_buf[3];
	u_char rdn_seq_len_buf[3];
	u_char rdn_set_len_buf[3];
	u_char dn_seq_len_buf[3];

	chunk_t asn1_oid_len     = { oid_len_buf,     0 };
	chunk_t asn1_name_len    = { name_len_buf,    0 };
	chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
	chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
	chunk_t asn1_dn_seq_len  = { dn_seq_len_buf,  0 };
	chunk_t oid  = chunk_empty;
	chunk_t name = chunk_empty;

	int whitespace  = 0;
	int rdn_seq_len = 0;
	int rdn_set_len = 0;
	int dn_seq_len  = 0;
	int pos         = 0;

	err_t ugh = NULL;

	u_char *dn_ptr = dn->ptr + 4;

	state_t state = SEARCH_OID;

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
					ugh = "unknown OID in distinguished name";
					state = UNKNOWN_OID;
					break;
				}
				code_asn1_length(x501rdns[pos].oid.len, &asn1_oid_len);

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
				code_asn1_length(name.len, &asn1_name_len);

				/* compute the length of the relative distinguished name sequence */
				rdn_seq_len = 1 + asn1_oid_len.len + x501rdns[pos].oid.len +
							  1 + asn1_name_len.len + name.len;
				code_asn1_length(rdn_seq_len, &asn1_rdn_seq_len);

				/* compute the length of the relative distinguished name set */
				rdn_set_len = 1 + asn1_rdn_seq_len.len + rdn_seq_len;
				code_asn1_length(rdn_set_len, &asn1_rdn_set_len);

				/* encode the relative distinguished name */
				*dn_ptr++ = ASN1_SET;
				chunkcpy(dn_ptr, asn1_rdn_set_len);
				*dn_ptr++ = ASN1_SEQUENCE;
				chunkcpy(dn_ptr, asn1_rdn_seq_len);
				*dn_ptr++ = ASN1_OID;
				chunkcpy(dn_ptr, asn1_oid_len);
				chunkcpy(dn_ptr, x501rdns[pos].oid);
				/* encode the ASN.1 character string type of the name */
				*dn_ptr++ = (x501rdns[pos].type == ASN1_PRINTABLESTRING
					&& !asn1_is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
				chunkcpy(dn_ptr, asn1_name_len);
				chunkcpy(dn_ptr, name);

				/* accumulate the length of the distinguished name sequence */
				dn_seq_len += 1 + asn1_rdn_set_len.len + rdn_set_len;

				/* reset name and change state */
				name = chunk_empty;
				state = SEARCH_OID;
			}
			break;
		case UNKNOWN_OID:
			break;
		}
	} while (*src++ != '\0');

	/* complete the distinguished name sequence*/
	code_asn1_length(dn_seq_len, &asn1_dn_seq_len);
	dn->ptr += 3 - asn1_dn_seq_len.len;
	dn->len =  1 + asn1_dn_seq_len.len + dn_seq_len;
	dn_ptr = dn->ptr;
	*dn_ptr++ = ASN1_SEQUENCE;
	chunkcpy(dn_ptr, asn1_dn_seq_len);
	return ugh;
}

/**
 * compare two distinguished names by comparing the individual RDNs
 */
bool same_dn(chunk_t a, chunk_t b)
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
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL
	||  init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
	{
		return FALSE;
	}

	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != NULL
		||  get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != NULL)
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
		   (type_a == ASN1_IA5STRING && asn1_known_oid(oid_a) == OID_EMAIL_ADDRESS)))
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

	/* the two DNs are equal! */
	return TRUE;
}


/**
 *  Compare two distinguished names by comparing the individual RDNs.
 *  A single'*' character designates a wildcard RDN in DN b.
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
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL
	||  init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
	{
		return FALSE;
	}

	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != NULL
		||  get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != NULL)
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
		   (type_a == ASN1_IA5STRING && asn1_known_oid(oid_a) == OID_EMAIL_ADDRESS)))
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
 * For each link pointing to the certificate increase the count by one
 */
void share_x509cert(x509cert_t *cert)
{
	if (cert != NULL)
	{
		cert->count++;
	}
}

/**
 *  Add a X.509 user/host certificate to the chained list
 */
x509cert_t* add_x509cert(x509cert_t *cert)
{
	certificate_t *certificate = cert->cert;
	x509cert_t *c = x509certs;

	while (c != NULL)
	{
		if (certificate->equals(certificate, c->cert)) /* already in chain, free cert */
		{
			free_x509cert(cert);
			return c;
		}
		c = c->next;
	}

	/* insert new cert at the root of the chain */
	lock_certs_and_keys("add_x509cert");
	cert->next = x509certs;
	x509certs = cert;
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("  x509 cert inserted")
	)
	unlock_certs_and_keys("add_x509cert");
	return cert;
}

/**
 * Choose either subject DN or a subjectAltName as connection end ID
 */
void select_x509cert_id(x509cert_t *cert, struct id *end_id)
{
	certificate_t *certificate = cert->cert;
	x509_t *x509 = (x509_t*)certificate;
	identification_t *subjectAltName;

	bool copy_subject_dn = TRUE;         /* ID is subject DN */

	if (end_id->kind != ID_ANY) /* check for matching subjectAltName */
	{
		enumerator_t *enumerator;

		enumerator = x509->create_subjectAltName_enumerator(x509);
		while (enumerator->enumerate(enumerator, &subjectAltName))
		{
			struct id id = empty_id;

			id_from_identification(&id, subjectAltName);
			if (same_id(&id, end_id))
			{
				copy_subject_dn = FALSE; /* take subjectAltName instead */
				break;
			}
		}
		enumerator->destroy(enumerator);
	}

	if (copy_subject_dn)
	{
		identification_t *subject = certificate->get_subject(certificate);
		chunk_t subject_dn = subject->get_encoding(subject);

		if (end_id->kind != ID_ANY && end_id->kind != ID_DER_ASN1_DN)
		{
			char buf[BUF_LEN];

			idtoa(end_id, buf, BUF_LEN);
			plog("  no subjectAltName matches ID '%s', replaced by subject DN", buf);
		}
		end_id->kind = ID_DER_ASN1_DN;
		end_id->name.len = subject_dn.len;
		end_id->name.ptr = temporary_cyclic_buffer();
		memcpy(end_id->name.ptr, subject_dn.ptr, subject_dn.len);
	}
}

/**
 * Check for equality between two key identifiers
 */
bool same_keyid(chunk_t a, chunk_t b)
{
	if (a.ptr == NULL || b.ptr == NULL)
	{
		return FALSE;
	}
	return chunk_equals(a, b);
}

/**
 * Get a X.509 certificate with a given issuer found at a certain position
 */
x509cert_t* get_x509cert(identification_t *issuer, chunk_t keyid, x509cert_t *chain)
{
	x509cert_t *cert = chain ? chain->next : x509certs;

	while (cert)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);

		if (keyid.ptr ? same_keyid(keyid, authKeyID) :
			certificate->has_issuer(certificate, issuer))
		{
			return cert;
		}
		cert = cert->next;
	}
	return NULL;
}

/**
 * Free the dynamic memory used to store generalNames
 */
void free_generalNames(generalName_t* gn, bool free_name)
{
	while (gn)
	{
		generalName_t *gn_top = gn;
		if (free_name)
		{
			free(gn->name.ptr);
		}
		gn = gn->next;
		free(gn_top);
	}
}

/**
 *  Free a X.509 certificate
 */
void free_x509cert(x509cert_t *cert)
{
	if (cert)
	{
		certificate_t *certificate = cert->cert;

		if (certificate)
		{
			certificate->destroy(certificate);
		}
		free(cert);
		cert = NULL;
	}
}

/**
 * Release of a certificate decreases the count by one
 * the certificate is freed when the counter reaches zero
 */
void release_x509cert(x509cert_t *cert)
{
	if (cert && --cert->count == 0)
	{
		x509cert_t **pp = &x509certs;
		while (*pp != cert)
		{
			pp = &(*pp)->next;
		}
		*pp = cert->next;
		free_x509cert(cert);
	}
}

/**
 * Stores a chained list of end certs and CA certs
 */
void store_x509certs(x509cert_t **firstcert, bool strict)
{
	x509cert_t *cacerts = NULL;
	x509cert_t **pp = firstcert;

	/* first extract CA certs, discarding root CA certs */

	while (*pp)
	{
		x509cert_t *cert = *pp;
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		x509_flag_t flags = x509->get_flags(x509);

		if (flags & X509_CA)
		{
			*pp = cert->next;

			/* we don't accept self-signed CA certs */
			if (flags & X509_SELF_SIGNED)
			{
				plog("self-signed cacert rejected");
				free_x509cert(cert);
			}
			else
			{
				/* insertion into temporary chain of candidate CA certs */
				cert->next = cacerts;
				cacerts = cert;
			}
		}
		else
		{
			pp = &cert->next;
		}
	}

	/* now verify the candidate CA certs */

	while (cacerts)
	{
		x509cert_t *cert = cacerts;

		cacerts = cacerts->next;

		if (trust_authcert_candidate(cert, cacerts))
		{
			add_authcert(cert, X509_CA);
		}
		else
		{
			plog("intermediate cacert rejected");
			free_x509cert(cert);
		}
	}

	/* now verify the end certificates */

	pp = firstcert;

	while (*pp)
	{
		time_t valid_until;
		x509cert_t *cert = *pp;

		if (verify_x509cert(cert, strict, &valid_until))
		{
			DBG(DBG_CONTROL | DBG_PARSING,
				DBG_log("public key validated")
			)
			add_x509_public_key(cert, valid_until, DAL_SIGNED);
		}
		else
		{
			plog("X.509 certificate rejected");
		}
		*pp = cert->next;
		free_x509cert(cert);
	}
}

/**
 * Check if a signature over binary blob is genuine
 */
bool x509_check_signature(chunk_t tbs, chunk_t sig, int algorithm,
						  certificate_t *issuer_cert)
{
	bool success;
	public_key_t *key;
	signature_scheme_t scheme;

	scheme = signature_scheme_from_oid(algorithm);
	if (scheme == SIGN_UNKNOWN)
	{
		return FALSE;
	}

	key = issuer_cert->get_public_key(issuer_cert);
	if (key == NULL)
	{
		return FALSE;
	}
	success = key->verify(key, scheme, tbs, sig);
	key->destroy(key);

	return success;
}

/**
 * Build an ASN.1 encoded PKCS#1 signature over a binary blob
 */
chunk_t x509_build_signature(chunk_t tbs, int algorithm, private_key_t *key,
							 bool bit_string)
{
	chunk_t signature;
	signature_scheme_t scheme = signature_scheme_from_oid(algorithm);

	if (scheme == SIGN_UNKNOWN || !key->sign(key, scheme, tbs, &signature))
	{
		return chunk_empty;
	}
	return (bit_string) ? asn1_bitstring("m", signature)
						: asn1_wrap(ASN1_OCTET_STRING, "m", signature);
}

/**
 * Extracts an otherName
 */
static bool parse_otherName(chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int oid = OID_UNKNOWN;
	bool success = FALSE;

	parser = asn1_parser_create(otherNameObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
		case ON_OBJ_ID_TYPE:
			oid = asn1_known_oid(object);
			break;
		case ON_OBJ_VALUE:
			if (oid == OID_XMPP_ADDR)
			{
				if (!asn1_parse_simple_object(&object, ASN1_UTF8STRING,
							parser->get_level(parser) + 1, "xmppAddr"))
				{
					goto end;
				}
			}
			break;
		default:
			break;
		}
	}
	success = parser->success(parser);

end:
	parser->destroy(parser);
	return success;
}


/**
 * Extracts a generalName
 */
static generalName_t* parse_generalName(chunk_t blob, int level0)
{
	u_char buf[BUF_LEN];
	asn1_parser_t *parser;
	chunk_t object;
	generalName_t *gn = NULL;
	int objectID;

	parser = asn1_parser_create(generalNameObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		bool valid_gn = FALSE;

		switch (objectID) {
		case GN_OBJ_RFC822_NAME:
		case GN_OBJ_DNS_NAME:
		case GN_OBJ_URI:
			DBG(DBG_PARSING,
				DBG_log("  '%.*s'", (int)object.len, object.ptr);
			)
			valid_gn = TRUE;
			break;
		case GN_OBJ_DIRECTORY_NAME:
			DBG(DBG_PARSING,
				dntoa(buf, BUF_LEN, object);
				DBG_log("  '%s'", buf)
			)
			valid_gn = TRUE;
			break;
		case GN_OBJ_IP_ADDRESS:
			DBG(DBG_PARSING,
				DBG_log("  '%d.%d.%d.%d'", *object.ptr, *(object.ptr+1),
									  *(object.ptr+2), *(object.ptr+3));
			)
			valid_gn = TRUE;
			break;
		case GN_OBJ_OTHER_NAME:
			if (!parse_otherName(object, parser->get_level(parser)+1))
			{
				goto end;
			}
			break;
		case GN_OBJ_X400_ADDRESS:
		case GN_OBJ_EDI_PARTY_NAME:
		case GN_OBJ_REGISTERED_ID:
			break;
		default:
			break;
		}

		if (valid_gn)
		{
			gn = malloc_thing(generalName_t);
			gn->kind = (objectID - GN_OBJ_OTHER_NAME) / 2;
			gn->name = object;
			gn->next = NULL;
			goto end;
		}
	}

end:
	parser->destroy(parser);
	return gn;
}

/**
 * Extracts one or several GNs and puts them into a chained list
 */
static generalName_t* parse_generalNames(chunk_t blob, int level0, bool implicit)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	generalName_t *top_gn = NULL;

	parser = asn1_parser_create(generalNamesObjects, blob);
	parser->set_top_level(parser, level0);
	parser->set_flags(parser, implicit, FALSE);

	while (parser->iterate(parser, &objectID, &object))
	{
		if (objectID == GENERAL_NAMES_GN)
		{
			generalName_t *gn = parse_generalName(object,
										parser->get_level(parser)+1);
			if (gn)
			{
				gn->next = top_gn;
				top_gn = gn;
			}
		}
	}
	parser->destroy(parser);

	return top_gn;
}

/**
 * Returns a directoryName
 */
chunk_t get_directoryName(chunk_t blob, int level, bool implicit)
{
	chunk_t name = chunk_empty;
	generalName_t * gn = parse_generalNames(blob, level, implicit);

	if (gn && gn->kind == GN_DIRECTORY_NAME)
	{
		name= gn->name;
	}
	free_generalNames(gn, FALSE);
	return name;
}

/**
 * Extracts an authoritykeyIdentifier
 */
void parse_authorityKeyIdentifier(chunk_t blob, int level0,
								  chunk_t *authKeyID,
								  chunk_t *authKeySerialNumber)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;

	parser = asn1_parser_create(authKeyIdentifierObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
		case AUTH_KEY_ID_KEY_ID:
			*authKeyID = object;
			break;
		case AUTH_KEY_ID_CERT_ISSUER:
			{
				generalName_t * gn = parse_generalNames(object,
										parser->get_level(parser) + 1, TRUE);

				free_generalNames(gn, FALSE);
			}
			break;
		case AUTH_KEY_ID_CERT_SERIAL:
			*authKeySerialNumber = object;
			break;
		default:
			break;
		}
	}
	parser->destroy(parser);
}

/**
 * Verifies a X.509 certificate
 */
bool verify_x509cert(const x509cert_t *cert, bool strict, time_t *until)
{
	int pathlen;

	*until = 0;

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
	{
		certificate_t *certificate = cert->cert;
		identification_t *subject = certificate->get_subject(certificate);
		identification_t *issuer  = certificate->get_issuer(certificate);
		x509_t *x509 = (x509_t*)certificate;
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
		x509cert_t *issuer_cert;
		time_t notBefore, notAfter;
		bool valid;

		DBG(DBG_CONTROL,
			DBG_log("subject: '%Y'", subject);
			DBG_log("issuer:  '%Y'", issuer);
			if (authKeyID.ptr)
			{
				DBG_log("authkey:  %#B", &authKeyID);
			}
		)

		valid = certificate->get_validity(certificate, NULL,
										  &notBefore, &notAfter);
		if (*until == UNDEFINED_TIME || notAfter < *until)
		{
			*until = notAfter;
		}
		if (!valid)
		{
			plog("certificate is invalid (valid from %T to %T)",
				 &notBefore, FALSE, &notAfter, FALSE);
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate is valid")
		)

		lock_authcert_list("verify_x509cert");
		issuer_cert = get_authcert(issuer, authKeyID, X509_CA);
		if (issuer_cert == NULL)
		{
			plog("issuer cacert not found");
			unlock_authcert_list("verify_x509cert");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("issuer cacert found")
		)

		if (!certificate->issued_by(certificate, issuer_cert->cert))
		{
			plog("certificate signature is invalid");
			unlock_authcert_list("verify_x509cert");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate signature is valid")
		)
		unlock_authcert_list("verify_x509cert");

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && (x509->get_flags(x509) & X509_SELF_SIGNED))
		{
			DBG(DBG_CONTROL,
				DBG_log("reached self-signed root ca")
			)
			return TRUE;
		}
		else
		{
			time_t nextUpdate = *until;
			time_t revocationDate = UNDEFINED_TIME;
			crl_reason_t revocationReason = CRL_REASON_UNSPECIFIED;

			/* first check certificate revocation using ocsp */
			cert_status_t status = verify_by_ocsp(cert, &nextUpdate
				, &revocationDate, &revocationReason);

			/* if ocsp service is not available then fall back to crl */
			if ((status == CERT_UNDEFINED)
			||  (status == CERT_UNKNOWN && strict))
			{
				status = verify_by_crl(cert, &nextUpdate, &revocationDate
					, &revocationReason);
			}

			switch (status)
			{
			case CERT_GOOD:
				/* if status information is stale */
				if (strict && nextUpdate < time(NULL))
				{
					DBG(DBG_CONTROL,
						DBG_log("certificate is good but status is stale")
					)
					remove_x509_public_key(cert);
					return FALSE;
				}
				DBG(DBG_CONTROL,
					DBG_log("certificate is good")
				)

				/* with strict crl policy the public key must have the same
				 * lifetime as the validity of the ocsp status or crl lifetime
				 */
				if (strict && nextUpdate < *until)
				{
					*until = nextUpdate;
				}
				break;
			case CERT_REVOKED:
				plog("certificate was revoked on %T, reason: %N"
					, &revocationDate, TRUE
					, crl_reason_names, revocationReason);
				remove_x509_public_key(cert);
				return FALSE;
			case CERT_UNKNOWN:
			case CERT_UNDEFINED:
			default:
				plog("certificate status unknown");
				if (strict)
				{
					remove_x509_public_key(cert);
					return FALSE;
				}
				break;
			}
		}

		/* go up one step in the trust chain */
		cert = issuer_cert;
	}
	plog("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
	return FALSE;
}

/**
 * List all X.509 certs in a chained list
 */
void list_x509cert_chain(const char *caption, x509cert_t* cert,
						 x509_flag_t flags, bool utc)
{
	bool first = TRUE;
	time_t now;

	/* determine the current time */
	time(&now);

	while (cert)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;

		if (flags == X509_NONE || (flags & x509->get_flags(x509)))
		{
			enumerator_t *enumerator;
			char buf[BUF_LEN];
			char *pos = buf;
			int len = BUF_LEN;
			bool first_altName = TRUE;
			identification_t *id;
			time_t notBefore, notAfter;
			public_key_t *key;
			chunk_t serial, keyid, subjkey, authkey;
			cert_t c;

			c.type = CERT_X509_SIGNATURE;
			c.u.x509 = cert;

			if (first)
			{
				whack_log(RC_COMMENT, " ");
				whack_log(RC_COMMENT, "List of X.509 %s Certificates:", caption);
				first = FALSE;
			}
			whack_log(RC_COMMENT, " ");

			enumerator = x509->create_subjectAltName_enumerator(x509);
			while (enumerator->enumerate(enumerator, &id))
			{
				int written;

				if (first_altName)
				{
					written = snprintf(pos, len, "%Y", id);
					first_altName = FALSE;
				}
				else
				{
					written = snprintf(pos, len, ", %Y", id);
				}
				pos += written;
				len -= written;
			}
			enumerator->destroy(enumerator);
			if (!first_altName)
			{
				whack_log(RC_COMMENT, "  altNames:  %s", buf);
			}

			whack_log(RC_COMMENT, "  subject:  \"%Y\"",
				certificate->get_subject(certificate));
			whack_log(RC_COMMENT, "  issuer:   \"%Y\"",
				certificate->get_issuer(certificate));
				serial = x509->get_serial(x509);
			whack_log(RC_COMMENT, "  serial:    %#B", &serial);

			/* list validity */
			certificate->get_validity(certificate, &now, &notBefore, &notAfter);
			whack_log(RC_COMMENT, "  validity:  not before %T %s",
				&notBefore, utc,
				(notBefore < now)?"ok":"fatal (not valid yet)");
			whack_log(RC_COMMENT, "             not after  %T %s",
				&notAfter, utc,
				check_expiry(notAfter, CA_CERT_WARNING_INTERVAL, TRUE));

			key = certificate->get_public_key(certificate);
			if (key);
			{
				whack_log(RC_COMMENT, "  pubkey:    %N %4d bits%s",
					key_type_names, key->get_type(key),
					key->get_keysize(key) * BITS_PER_BYTE,				
					cert->smartcard ? ", on smartcard" :
					(has_private_key(c)? ", has private key" : ""));

				if (key->get_fingerprint(key, KEY_ID_PUBKEY_INFO_SHA1, &keyid))
				{
					whack_log(RC_COMMENT, "  keyid:     %#B", &keyid);
				}
				if (key->get_fingerprint(key, KEY_ID_PUBKEY_SHA1, &subjkey))
				{
					whack_log(RC_COMMENT, "  subjkey:   %#B", &subjkey);
				}
				key->destroy(key);
			}

			/* list optional authorityKeyIdentifier */
			authkey = x509->get_authKeyIdentifier(x509);
			if (authkey.ptr)
			{
				whack_log(RC_COMMENT, "  authkey:   %#B", &authkey);
			}
		}
		cert = cert->next;
	}
}

/**
 * List all X.509 end certificates in a chained list
 */
void list_x509_end_certs(bool utc)
{
	list_x509cert_chain("End Entity", x509certs, X509_NONE, utc);
}
