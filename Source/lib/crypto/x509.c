/**
 * @file x509.c
 * 
 * @brief Implementation of x509_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "x509.h"

#include <daemon.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <utils/logger_manager.h>

typedef const char *err_t;	/* error message, or NULL for success */

#define chunkcpy(dst, chunk) { memcpy(dst, chunk.ptr, chunk.len); dst += chunk.len;}

#define BUF_LEN 512
#define RSA_MIN_OCTETS	(512 / 8)
#define RSA_MIN_OCTETS_UGH	"RSA modulus too small for security: less than 512 bits"
#define RSA_MAX_OCTETS	(8192 / 8)
#define RSA_MAX_OCTETS_UGH	"RSA modulus too large: more than 8192 bits"

logger_t *logger;

typedef enum generalNames_t generalNames_t;

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

typedef struct generalName_t generalName_t;

/**
 * A generalName, chainable in a list
 */
struct generalName_t {
	generalName_t *next;
	generalNames_t kind;
	chunk_t name;
};

typedef struct private_x509_t private_x509_t;

/**
 * Private data of a x509_t object.
 */
struct private_x509_t {
	/**
	 * Public interface for this certificate.
	 */
	x509_t public;
	
	time_t installed;
	u_char authority_flags;
	chunk_t x509;
	chunk_t tbsCertificate;
	u_int version;
	chunk_t serialNumber;
	/*   signature */
	int sigAlg;
	chunk_t issuer;
	/*   validity */
	time_t notBefore;
	time_t notAfter;
	chunk_t subject;
	/* subjectPublicKeyInfo */
	auth_method_t subjectPublicKeyAlgorithm;
	chunk_t subjectPublicKey;
	rsa_public_key_t *public_key;
	/*   issuerUniqueID */
	/*   subjectUniqueID */
	/*   v3 extensions */
	/*   extension */
	/*     extension */
	/*       extnID */
	/*       critical */
	/*       extnValue */
	bool isCA;
	bool isOcspSigner; /* ocsp */
	chunk_t subjectKeyID;
	chunk_t authKeyID;
	chunk_t authKeySerialNumber;
	chunk_t accessLocation; /* ocsp */
	generalName_t *subjectAltName;
	generalName_t *crlDistributionPoints;
	/* signatureAlgorithm */
	int algorithm;
	chunk_t signature;
};

/**
 * ASN.1 definition of a basicConstraints extension 
 */
static const asn1Object_t basicConstraintsObjects[] = {
	{ 0, "basicConstraints",	ASN1_SEQUENCE,	ASN1_NONE			}, /*  0 */
	{ 1,   "CA",				ASN1_BOOLEAN,	ASN1_DEF|ASN1_BODY	}, /*  1 */
	{ 1,   "pathLenConstraint",	ASN1_INTEGER,	ASN1_OPT|ASN1_BODY	}, /*  2 */
	{ 1,   "end opt",			ASN1_EOC,		ASN1_END  			}  /*  3 */
};
#define BASIC_CONSTRAINTS_CA	1
#define BASIC_CONSTRAINTS_ROOF	4

/**
 * ASN.1 definition of time
 */
static const asn1Object_t timeObjects[] = {
	{ 0,   "utcTime",		ASN1_UTCTIME,			ASN1_OPT|ASN1_BODY 	}, /*  0 */
	{ 0,   "end opt",		ASN1_EOC,				ASN1_END  			}, /*  1 */
	{ 0,   "generalizeTime",ASN1_GENERALIZEDTIME,	ASN1_OPT|ASN1_BODY 	}, /*  2 */
	{ 0,   "end opt",		ASN1_EOC,				ASN1_END  			}  /*  3 */
};
#define TIME_UTC			0
#define TIME_GENERALIZED	2
#define TIME_ROOF			4

/** 
 * ASN.1 definition of a keyIdentifier 
 */
static const asn1Object_t keyIdentifierObjects[] = {
	{ 0,   "keyIdentifier",	ASN1_OCTET_STRING,	ASN1_BODY }  /*  0 */
};

/**
 * ASN.1 definition of a authorityKeyIdentifier extension 
 */
static const asn1Object_t authorityKeyIdentifierObjects[] = {
	{ 0,   "authorityKeyIdentifier",	ASN1_SEQUENCE,		ASN1_NONE 			}, /*  0 */
	{ 1,     "keyIdentifier",			ASN1_CONTEXT_S_0,	ASN1_OPT|ASN1_OBJ	}, /*  1 */
	{ 1,     "end opt",					ASN1_EOC,			ASN1_END  			}, /*  2 */
	{ 1,     "authorityCertIssuer",		ASN1_CONTEXT_C_1,	ASN1_OPT|ASN1_OBJ	}, /*  3 */
	{ 1,     "end opt",					ASN1_EOC,			ASN1_END  			}, /*  4 */
	{ 1,     "authorityCertSerialNumber",ASN1_CONTEXT_S_2,  ASN1_OPT|ASN1_BODY	}, /*  5 */
	{ 1,     "end opt",					ASN1_EOC,			ASN1_END  			}  /*  6 */
};
#define AUTH_KEY_ID_KEY_ID			1
#define AUTH_KEY_ID_CERT_ISSUER		3
#define AUTH_KEY_ID_CERT_SERIAL		5
#define AUTH_KEY_ID_ROOF			7

/**
 * ASN.1 definition of a authorityInfoAccess extension 
 */
static const asn1Object_t authorityInfoAccessObjects[] = {
	{ 0,   "authorityInfoAccess",	ASN1_SEQUENCE,	ASN1_LOOP }, /*  0 */
	{ 1,     "accessDescription",	ASN1_SEQUENCE,	ASN1_NONE }, /*  1 */
	{ 2,       "accessMethod",		ASN1_OID,		ASN1_BODY }, /*  2 */
	{ 2,       "accessLocation",	ASN1_EOC,		ASN1_RAW  }, /*  3 */
	{ 0,   "end loop",				ASN1_EOC,		ASN1_END  }  /*  4 */
};
#define AUTH_INFO_ACCESS_METHOD		2
#define AUTH_INFO_ACCESS_LOCATION	3
#define AUTH_INFO_ACCESS_ROOF		5

/**
 * ASN.1 definition of a extendedKeyUsage extension
 */
static const asn1Object_t extendedKeyUsageObjects[] = {
	{ 0, "extendedKeyUsage",	ASN1_SEQUENCE,	ASN1_LOOP }, /*  0 */
	{ 1,   "keyPurposeID",		ASN1_OID,		ASN1_BODY }, /*  1 */
	{ 0, "end loop",			ASN1_EOC,		ASN1_END  }, /*  2 */
};

#define EXT_KEY_USAGE_PURPOSE_ID	1
#define EXT_KEY_USAGE_ROOF			3

/**
 * ASN.1 definition of generalNames 
 */
static const asn1Object_t generalNamesObjects[] = {
	{ 0, "generalNames",	ASN1_SEQUENCE,	ASN1_LOOP }, /*  0 */
	{ 1,   "generalName",	ASN1_EOC,		ASN1_RAW  }, /*  1 */
	{ 0, "end loop",		ASN1_EOC,		ASN1_END  }  /*  2 */
};
#define GENERAL_NAMES_GN	1
#define GENERAL_NAMES_ROOF	3

/**
 * ASN.1 definition of generalName 
 */
static const asn1Object_t generalNameObjects[] = {
  { 0,   "otherName",		ASN1_CONTEXT_C_0,  ASN1_OPT|ASN1_BODY	}, /*  0 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /*  1 */
  { 0,   "rfc822Name",		ASN1_CONTEXT_S_1,  ASN1_OPT|ASN1_BODY	}, /*  2 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END 			}, /*  3 */
  { 0,   "dnsName",			ASN1_CONTEXT_S_2,  ASN1_OPT|ASN1_BODY	}, /*  4 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /*  5 */
  { 0,   "x400Address",		ASN1_CONTEXT_S_3,  ASN1_OPT|ASN1_BODY	}, /*  6 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /*  7 */
  { 0,   "directoryName",	ASN1_CONTEXT_C_4,  ASN1_OPT|ASN1_BODY	}, /*  8 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /*  9 */
  { 0,   "ediPartyName",	ASN1_CONTEXT_C_5,  ASN1_OPT|ASN1_BODY	}, /* 10 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /* 11 */
  { 0,   "URI",				ASN1_CONTEXT_S_6,  ASN1_OPT|ASN1_BODY	}, /* 12 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /* 13 */
  { 0,   "ipAddress",		ASN1_CONTEXT_S_7,  ASN1_OPT|ASN1_BODY	}, /* 14 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}, /* 15 */
  { 0,   "registeredID",	ASN1_CONTEXT_S_8,  ASN1_OPT|ASN1_BODY	}, /* 16 */
  { 0,   "end choice",		ASN1_EOC,          ASN1_END				}  /* 17 */
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

/**
 * SN.1 definition of crlDistributionPoints
 */
static const asn1Object_t crlDistributionPointsObjects[] = {
	{ 0, "crlDistributionPoints",	ASN1_SEQUENCE,		ASN1_LOOP			}, /*  0 */
	{ 1,   "DistributionPoint",		ASN1_SEQUENCE,		ASN1_NONE			}, /*  1 */
	{ 2,     "distributionPoint",	ASN1_CONTEXT_C_0,	ASN1_OPT|ASN1_LOOP	}, /*  2 */
	{ 3,       "fullName",			ASN1_CONTEXT_C_0,	ASN1_OPT|ASN1_OBJ	}, /*  3 */
	{ 3,       "end choice",		ASN1_EOC,			ASN1_END			}, /*  4 */
	{ 3,       "nameRelToCRLIssuer",ASN1_CONTEXT_C_1,	ASN1_OPT|ASN1_BODY	}, /*  5 */
	{ 3,       "end choice",		ASN1_EOC,			ASN1_END			}, /*  6 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /*  7 */
	{ 2,     "reasons",				ASN1_CONTEXT_C_1,	ASN1_OPT|ASN1_BODY	}, /*  8 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /*  9 */
	{ 2,     "crlIssuer",			ASN1_CONTEXT_C_2,	ASN1_OPT|ASN1_BODY	}, /* 10 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 11 */
	{ 0, "end loop",				ASN1_EOC,			ASN1_END			}, /* 12 */
};
#define CRL_DIST_POINTS_FULLNAME	 3
#define CRL_DIST_POINTS_ROOF		13

/**
 * ASN.1 definition of an X.509v3 x509
 */
static const asn1Object_t certObjects[] = {
	{ 0, "x509",				ASN1_SEQUENCE,		ASN1_OBJ			}, /*  0 */
	{ 1,   "tbsCertificate",		ASN1_SEQUENCE,		ASN1_OBJ			}, /*  1 */
	{ 2,     "DEFAULT v1",			ASN1_CONTEXT_C_0,	ASN1_DEF			}, /*  2 */
	{ 3,       "version",			ASN1_INTEGER,		ASN1_BODY			}, /*  3 */
	{ 2,     "serialNumber",		ASN1_INTEGER,		ASN1_BODY			}, /*  4 */
	{ 2,     "signature",			ASN1_EOC,			ASN1_RAW			}, /*  5 */
	{ 2,     "issuer",				ASN1_SEQUENCE,		ASN1_OBJ			}, /*  6 */
	{ 2,     "validity",			ASN1_SEQUENCE,		ASN1_NONE			}, /*  7 */
	{ 3,       "notBefore",			ASN1_EOC,			ASN1_RAW			}, /*  8 */
	{ 3,       "notAfter",			ASN1_EOC,			ASN1_RAW			}, /*  9 */
	{ 2,     "subject",				ASN1_SEQUENCE,		ASN1_OBJ			}, /* 10 */
	{ 2,     "subjectPublicKeyInfo",ASN1_SEQUENCE,		ASN1_NONE			}, /* 11 */
	{ 3,       "algorithm",			ASN1_EOC,			ASN1_RAW			}, /* 12 */
	{ 3,       "subjectPublicKey",	ASN1_BIT_STRING,	ASN1_NONE			}, /* 13 */
	{ 4,         "RSAPublicKey",	ASN1_SEQUENCE,		ASN1_RAW			}, /* 14 */
	{ 2,     "issuerUniqueID",		ASN1_CONTEXT_C_1,	ASN1_OPT			}, /* 15 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 16 */
	{ 2,     "subjectUniqueID",		ASN1_CONTEXT_C_2,	ASN1_OPT			}, /* 17 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 18 */
	{ 2,     "optional extensions",	ASN1_CONTEXT_C_3,	ASN1_OPT			}, /* 19 */
	{ 3,       "extensions",		ASN1_SEQUENCE,		ASN1_LOOP			}, /* 20 */
	{ 4,         "extension",		ASN1_SEQUENCE,		ASN1_NONE			}, /* 21 */
	{ 5,           "extnID",		ASN1_OID,			ASN1_BODY			}, /* 22 */
	{ 5,           "critical",		ASN1_BOOLEAN,		ASN1_DEF|ASN1_BODY	}, /* 23 */
	{ 5,           "extnValue",		ASN1_OCTET_STRING,	ASN1_BODY			}, /* 24 */
	{ 3,       "end loop",			ASN1_EOC,			ASN1_END			}, /* 25 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 26 */
	{ 1,   "signatureAlgorithm",	ASN1_EOC,			ASN1_RAW			}, /* 27 */
	{ 1,   "signatureValue",		ASN1_BIT_STRING,	ASN1_BODY			}  /* 28 */
};
#define X509_OBJ_CERTIFICATE					 0
#define X509_OBJ_TBS_CERTIFICATE				 1
#define X509_OBJ_VERSION						 3
#define X509_OBJ_SERIAL_NUMBER					 4
#define X509_OBJ_SIG_ALG						 5
#define X509_OBJ_ISSUER 						 6
#define X509_OBJ_NOT_BEFORE						 8
#define X509_OBJ_NOT_AFTER						 9
#define X509_OBJ_SUBJECT						10
#define X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM	12
#define X509_OBJ_SUBJECT_PUBLIC_KEY				13
#define X509_OBJ_RSA_PUBLIC_KEY					14
#define X509_OBJ_EXTN_ID						22
#define X509_OBJ_CRITICAL						23
#define X509_OBJ_EXTN_VALUE						24
#define X509_OBJ_ALGORITHM						27
#define X509_OBJ_SIGNATURE						28
#define X509_OBJ_ROOF							29



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
	{"E", 				{oid_E,      9}, ASN1_IA5STRING},
	{"Email", 			{oid_E,      9}, ASN1_IA5STRING},
	{"emailAddress",	{oid_E,      9}, ASN1_IA5STRING},
	{"UN", 				{oid_UN,     9}, ASN1_IA5STRING},
	{"unstructuredName",{oid_UN,     9}, ASN1_IA5STRING},
	{"TCGID", 			{oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};

#define X501_RDN_ROOF   24

static u_char ASN1_subjectAltName_oid_str[] = {
	0x06, 0x03, 0x55, 0x1D, 0x11
};

static const chunk_t ASN1_subjectAltName_oid = chunk_from_buf(ASN1_subjectAltName_oid_str);


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
static err_t init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
	*rdn = CHUNK_INITIALIZER;
	*attribute = CHUNK_INITIALIZER;
	
	/* a DN is a SEQUENCE OF RDNs */
	if (*dn.ptr != ASN1_SEQUENCE)
	{
		return "DN is not a SEQUENCE";
	}
	
	rdn->len = asn1_length(&dn);
	
	if (rdn->len == ASN1_INVALID_LENGTH)
		return "Invalid RDN length";
	
	rdn->ptr = dn.ptr;
	
	/* are there any RDNs ? */
	*next = rdn->len > 0;
	
	return NULL;
}

/**
 * Fetches the next RDN in a DN
 */
static err_t get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid, chunk_t *value, asn1_t *type, bool *next)
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

	if (ugh != NULL)
	{/* a parsing error has occured */
		return ugh;
	}

	while (next)
	{
		ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

		if (ugh != NULL)
		{ /* a parsing error has occured */
			return ugh;
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
	return NULL;
}

/**
 * Count the number of wildcard RDNs in a distinguished name
 */
int dn_count_wildcards(chunk_t dn)
{
	chunk_t rdn, attribute, oid, value;
	asn1_t type;
	bool next;
	int wildcards = 0;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh != NULL) 
	{ /* a parsing error has occured */
		return -1;
	}
	
	while (next)
	{
		ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);
		if (ugh != NULL) 
		{/* a parsing error has occured */
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
 * Converts a binary DER-encoded ASN.1 distinguished name
 * into LDAP-style human-readable ASCII format
 */
int dntoa(char *dst, size_t dstlen, chunk_t dn)
{
	err_t ugh = NULL;
	chunk_t str;

	str.ptr = dst;
	str.len = dstlen;
	ugh = dn_parse(dn, &str);

	if (ugh != NULL) /* error, print DN as hex string */
	{
		logger->log(logger, ERROR|LEVEL1, "error in DN parsing: %s", ugh);
		str.ptr = dst;
		str.len = dstlen;
		hex_str(dn, &str);
	}
	return (int)(dstlen - str.len);
}

/**
 * Same as dntoa but prints a special string for a null dn
 */
int dntoa_or_null(char *dst, size_t dstlen, chunk_t dn, const char* null_dn)
{
	if (dn.ptr == NULL)
	{
		return snprintf(dst, dstlen, "%s", null_dn);
	}
	else
	{
		return dntoa(dst, dstlen, dn);
	}
}

/**
 * Converts an LDAP-style human-readable ASCII-encoded
 * ASN.1 distinguished name into binary DER-encoded format
 */
err_t atodn(char *src, chunk_t *dn)
{
	/* finite state machine for atodn */
	typedef enum {
		SEARCH_OID =	0,
		READ_OID =		1,
		SEARCH_NAME =	2,
		READ_NAME =		3,
		UNKNOWN_OID =	4
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
	chunk_t oid  = CHUNK_INITIALIZER;
	chunk_t name = CHUNK_INITIALIZER;
	
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
					oid.len++;
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
							&& !is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
					chunkcpy(dn_ptr, asn1_name_len);
					chunkcpy(dn_ptr, name);

					/* accumulate the length of the distinguished name sequence */
					dn_seq_len += 1 + asn1_rdn_set_len.len + rdn_set_len;

					/* reset name and change state */
					name = CHUNK_INITIALIZER;
					state = SEARCH_OID;
				}
				break;
			case UNKNOWN_OID:
				break;
		}
	} while (*src++ != '\0');

	/* complete the distinguished name sequence */
	code_asn1_length(dn_seq_len, &asn1_dn_seq_len);
	dn->ptr += 3 - asn1_dn_seq_len.len;
	dn->len =  1 + asn1_dn_seq_len.len + dn_seq_len;
	dn_ptr = dn->ptr;
	*dn_ptr++ = ASN1_SEQUENCE;
	chunkcpy(dn_ptr, asn1_dn_seq_len);
	return ugh;
}

/**
 * compare two distinguished names by
 * comparing the individual RDNs
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
	if (memcmp(a.ptr, b.ptr, b.len) == 0)
	{
		return TRUE;
	}
 
	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
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
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
	{
		return FALSE;
	}
	/* fetch next RDN pair */
	while (next_a && next_b)
	{
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a, &type_a, &next_a) != NULL ||
			get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b, &type_b, &next_b) != NULL)
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
 * compare two X.509 x509s by comparing their signatures
 */
static bool equals(private_x509_t *this, private_x509_t *other)
{
	return chunk_equals(this->signature, other->signature);
}

/**
 * encode a linked list of subjectAltNames
 */
chunk_t build_subjectAltNames(generalName_t *subjectAltNames)
{
	u_char *pos;
	chunk_t names;
	size_t len = 0;
	generalName_t *gn = subjectAltNames;
	
	/* compute the total size of the ASN.1 attributes object */
	while (gn != NULL)
	{
		len += gn->name.len;
		gn = gn->next;
	}

	pos = build_asn1_object(&names, ASN1_SEQUENCE, len);

	gn = subjectAltNames;
	while (gn != NULL)
	{
		chunkcpy(pos, gn->name);
		gn = gn->next;
	}

	return asn1_wrap(ASN1_SEQUENCE, "cm",
					 ASN1_subjectAltName_oid,
					 asn1_wrap(ASN1_OCTET_STRING, "m", names)
					);
}

/**
 * free the dynamic memory used to store generalNames
 */
void free_generalNames(generalName_t* gn, bool free_name)
{
	while (gn != NULL)
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
 * extracts the basicConstraints extension
 */
static bool parse_basicConstraints(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	bool isCA = FALSE;

	asn1_init(&ctx, blob, level0, FALSE);

	while (objectID < BASIC_CONSTRAINTS_ROOF) {

		if (!extract_object(basicConstraintsObjects, &objectID, &object,&level, &ctx))
		{
			break;
		}
		if (objectID == BASIC_CONSTRAINTS_CA)
		{
			isCA = object.len && *object.ptr;
			logger->log(logger, RAW|LEVEL1, "  %s", isCA ? "TRUE" : "FALSE");
		}
		objectID++;
	}
	return isCA;
}

/**
 * extracts an otherName
 */
static bool parse_otherName(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	int objectID = 0;
	u_int level;
	int oid = OID_UNKNOWN;

	asn1_init(&ctx, blob, level0, FALSE);

	while (objectID < ON_OBJ_ROOF)
	{
		if (!extract_object(otherNameObjects, &objectID, &object, &level, &ctx))
			return FALSE;

		switch (objectID)
		{
			case ON_OBJ_ID_TYPE:
				oid = known_oid(object);
				break;
			case ON_OBJ_VALUE:
				if (oid == OID_XMPP_ADDR)
				{
					if (!parse_asn1_simple_object(&object, ASN1_UTF8STRING, level + 1, "xmppAddr"))
					{
						return FALSE;
					}
				}
				break;
			default:
				break;
		}
		objectID++;
	}
	return TRUE;
}


/**
 * extracts a generalName
 */
static generalName_t* parse_generalName(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	int objectID = 0;
	u_int level;

	asn1_init(&ctx, blob, level0, FALSE);

	while (objectID < GN_OBJ_ROOF)
	{
		bool valid_gn = FALSE;
	
		if (!extract_object(generalNameObjects, &objectID, &object, &level, &ctx))
			return NULL;

		switch (objectID) {
			case GN_OBJ_RFC822_NAME:
			case GN_OBJ_DNS_NAME:
			case GN_OBJ_URI:
				logger->log(logger, RAW|LEVEL1, "  '%.*s'", (int)object.len, object.ptr);
				valid_gn = TRUE;
				break;
			case GN_OBJ_DIRECTORY_NAME:
				valid_gn = TRUE;
				break;
			case GN_OBJ_IP_ADDRESS:
				logger->log(logger, RAW|LEVEL1, "  '%d.%d.%d.%d'", 
							*object.ptr, *(object.ptr+1),
							*(object.ptr+2), *(object.ptr+3));
				valid_gn = TRUE;
				break;
			case GN_OBJ_OTHER_NAME:
				if (!parse_otherName(object, level + 1))
					return NULL;
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
			generalName_t *gn = malloc_thing(generalName_t);
			gn->kind = (objectID - GN_OBJ_OTHER_NAME) / 2;
			gn->name = object;
			gn->next = NULL;
			return gn;
		}
		objectID++;
	}
	return NULL;
}

/**
 * extracts one or several GNs and puts them into a chained list
 */
static generalName_t* parse_generalNames(chunk_t blob, int level0, bool implicit)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;

	generalName_t *top_gn = NULL;

	asn1_init(&ctx, blob, level0, implicit);

	while (objectID < GENERAL_NAMES_ROOF)
	{
		if (!extract_object(generalNamesObjects, &objectID, &object, &level, &ctx))
			return NULL;
		
		if (objectID == GENERAL_NAMES_GN)
		{
			generalName_t *gn = parse_generalName(object, level+1);
			if (gn != NULL)
			{
				gn->next = top_gn;
				top_gn = gn;
			}
		}
		objectID++;
	}
	return top_gn;
}

/**
 * returns a directoryName
 */
chunk_t get_directoryName(chunk_t blob, int level, bool implicit)
{
	chunk_t name = CHUNK_INITIALIZER;
	generalName_t * gn = parse_generalNames(blob, level, implicit);

	if (gn != NULL && gn->kind == GN_DIRECTORY_NAME)
	{
		name= gn->name;
	}

	free_generalNames(gn, FALSE);

	return name;
}

/**
 * extracts and converts a UTCTIME or GENERALIZEDTIME object
 */
time_t parse_time(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, FALSE);
	
	while (objectID < TIME_ROOF)
	{
		if (!extract_object(timeObjects, &objectID, &object, &level, &ctx))
			return 0;
		
		if (objectID == TIME_UTC || objectID == TIME_GENERALIZED)
		{
			return asn1totime(&object, (objectID == TIME_UTC)
					? ASN1_UTCTIME : ASN1_GENERALIZEDTIME);
		}
		objectID++;
	}
	return 0;
}

/**
 * extracts a keyIdentifier
 */
static chunk_t parse_keyIdentifier(chunk_t blob, int level0, bool implicit)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, implicit);
	
	extract_object(keyIdentifierObjects, &objectID, &object, &level, &ctx);
	return object;
}

/**
 * extracts an authoritykeyIdentifier
 */
void parse_authorityKeyIdentifier(chunk_t blob, int level0 , chunk_t *authKeyID, chunk_t *authKeySerialNumber)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, FALSE);
	while (objectID < AUTH_KEY_ID_ROOF)
	{
		if (!extract_object(authorityKeyIdentifierObjects, &objectID, &object, &level, &ctx))
		{
			return;
		}
		switch (objectID) 
		{
			case AUTH_KEY_ID_KEY_ID:
				*authKeyID = parse_keyIdentifier(object, level+1, TRUE);
				break;
			case AUTH_KEY_ID_CERT_ISSUER:
			{
				generalName_t *gn = parse_generalNames(object, level+1, TRUE);
				free_generalNames(gn, FALSE);
				break;
			}
			case AUTH_KEY_ID_CERT_SERIAL:
				*authKeySerialNumber = object;
				break;
			default:
				break;
		}
		objectID++;
	}
}

/**
 * extracts an authorityInfoAcess location
 */
static void parse_authorityInfoAccess(chunk_t blob, int level0, chunk_t *accessLocation)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	u_int accessMethod = OID_UNKNOWN;
	
	asn1_init(&ctx, blob, level0, FALSE);
	while (objectID < AUTH_INFO_ACCESS_ROOF)
	{
		if (!extract_object(authorityInfoAccessObjects, &objectID, &object, &level, &ctx))
		{
			return;
		}
		switch (objectID) 
		{
			case AUTH_INFO_ACCESS_METHOD:
				accessMethod = known_oid(object);
				break;
			case AUTH_INFO_ACCESS_LOCATION:
			{
				switch (accessMethod)
				{
					case OID_OCSP:
						if (*object.ptr == ASN1_CONTEXT_S_6)
						{
							if (asn1_length(&object) == ASN1_INVALID_LENGTH)
							{
								return;
							}
							logger->log(logger, RAW|LEVEL1, "  '%.*s'",(int)object.len, object.ptr);
							/* only HTTP(S) URIs accepted */
							if (strncasecmp(object.ptr, "http", 4) == 0)
							{
								*accessLocation = object;
								return;
							}
						}
						logger->log(logger, ERROR|LEVEL2, "ignoring OCSP InfoAccessLocation with unkown protocol");
						break;
					default:
						/* unkown accessMethod, ignoring */
						break;
				}
				break;
			}
			default:
				break;
		}
		objectID++;
	}
}

/**
 * extracts extendedKeyUsage OIDs
 */
static bool parse_extendedKeyUsage(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, FALSE);
	while (objectID < EXT_KEY_USAGE_ROOF)
	{
		if (!extract_object(extendedKeyUsageObjects, &objectID, &object, &level, &ctx))
		{
			return FALSE;
		}
		if (objectID == EXT_KEY_USAGE_PURPOSE_ID && 
			known_oid(object) == OID_OCSP_SIGNING)
		{
			return TRUE;
		}
		objectID++;
	}
	return FALSE;
}

/**
 * extracts one or several crlDistributionPoints and puts them into
 * a chained list
 */
static generalName_t* parse_crlDistributionPoints(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	generalName_t *top_gn = NULL;      /* top of the chained list */
	generalName_t **tail_gn = &top_gn; /* tail of the chained list */
	
	asn1_init(&ctx, blob, level0, FALSE);
	while (objectID < CRL_DIST_POINTS_ROOF)
	{
		if (!extract_object(crlDistributionPointsObjects, &objectID, &object, &level, &ctx))
		{
			return NULL;
		}
		if (objectID == CRL_DIST_POINTS_FULLNAME)
		{
			generalName_t *gn = parse_generalNames(object, level+1, TRUE);
			/* append extracted generalNames to existing chained list */
			*tail_gn = gn;
			/* find new tail of the chained list */
			while (gn != NULL)
			{
				tail_gn = &gn->next;  gn = gn->next;
			}
		}
		objectID++;
	}
	return top_gn;
}


/**
 * Parses an X.509v3 x509
 */
bool parse_x509cert(chunk_t blob, u_int level0, private_x509_t *cert)
{
	u_char buf[BUF_LEN];
	asn1_ctx_t ctx;
	bool critical;
	chunk_t object;
	u_int level;
	u_int extn_oid = OID_UNKNOWN;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, FALSE);
	while (objectID < X509_OBJ_ROOF)
	{
		if (!extract_object(certObjects, &objectID, &object, &level, &ctx))
		{
			return FALSE;
		}
		/* those objects which will parsed further need the next higher level */
		level++;
		switch (objectID) {
			case X509_OBJ_CERTIFICATE:
				cert->x509 = object;
				break;
			case X509_OBJ_TBS_CERTIFICATE:
				cert->tbsCertificate = object;
				break;
			case X509_OBJ_VERSION:
				cert->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
				logger->log(logger, RAW|LEVEL1, "  v%d", cert->version);
				break;
			case X509_OBJ_SERIAL_NUMBER:
				cert->serialNumber = object;
				break;
			case X509_OBJ_SIG_ALG:
				cert->sigAlg = parse_algorithmIdentifier(object, level, NULL);
				break;
			case X509_OBJ_ISSUER:
				cert->issuer = object;
				dntoa(buf, BUF_LEN, object);
				logger->log(logger, RAW|LEVEL1, "  '%s'", buf);
				break;
			case X509_OBJ_NOT_BEFORE:
				cert->notBefore = parse_time(object, level);
				break;
			case X509_OBJ_NOT_AFTER:
				cert->notAfter = parse_time(object, level);
				break;
			case X509_OBJ_SUBJECT:
				cert->subject = object;
				dntoa(buf, BUF_LEN, object);
				logger->log(logger, RAW|LEVEL1, "  '%s'", buf);
				break;
			case X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM:
				if (parse_algorithmIdentifier(object, level, NULL) == OID_RSA_ENCRYPTION)
				{
					cert->subjectPublicKeyAlgorithm = RSA_DIGITAL_SIGNATURE;
				}
				else
				{
					logger->log(logger, ERROR|LEVEL1, "  unsupported public key algorithm");
					return FALSE;
				}
				break;
			case X509_OBJ_SUBJECT_PUBLIC_KEY:
				if (ctx.blobs[4].len > 0 && *ctx.blobs[4].ptr == 0x00)
				{
					/* skip initial bit string octet defining 0 unused bits */
					ctx.blobs[4].ptr++; ctx.blobs[4].len--;
				}
				else
				{
					logger->log(logger, ERROR|LEVEL1, "  invalid RSA public key format");
					return FALSE;
				}
				break;
			case X509_OBJ_RSA_PUBLIC_KEY:
				cert->subjectPublicKey = object;
				break;
			case X509_OBJ_EXTN_ID:
				extn_oid = known_oid(object);
				break;
			case X509_OBJ_CRITICAL:
				critical = object.len && *object.ptr;
				logger->log(logger, ERROR|LEVEL1, "  %s", critical ? "TRUE" : "FALSE");
				break;
			case X509_OBJ_EXTN_VALUE:
			{
				switch (extn_oid) {
					case OID_SUBJECT_KEY_ID:
						cert->subjectKeyID = parse_keyIdentifier(object, level, FALSE);
						break;
					case OID_SUBJECT_ALT_NAME:
						cert->subjectAltName = parse_generalNames(object, level, FALSE);
						break;
					case OID_BASIC_CONSTRAINTS:
						cert->isCA = parse_basicConstraints(object, level);
						break;
					case OID_CRL_DISTRIBUTION_POINTS:
						cert->crlDistributionPoints = parse_crlDistributionPoints(object, level);
						break;
					case OID_AUTHORITY_KEY_ID:
						parse_authorityKeyIdentifier(object, level , &cert->authKeyID, &cert->authKeySerialNumber);
						break;
					case OID_AUTHORITY_INFO_ACCESS:
						parse_authorityInfoAccess(object, level, &cert->accessLocation);
						break;
					case OID_EXTENDED_KEY_USAGE:
						cert->isOcspSigner = parse_extendedKeyUsage(object, level);
						break;
					case OID_NS_REVOCATION_URL:
					case OID_NS_CA_REVOCATION_URL:
					case OID_NS_CA_POLICY_URL:
					case OID_NS_COMMENT:
						if (!parse_asn1_simple_object(&object, ASN1_IA5STRING , level, oid_names[extn_oid].name))
						{
							return FALSE;
						}
						break;
					default:
						break;
				}
				break;
			}
			case X509_OBJ_ALGORITHM:
				cert->algorithm = parse_algorithmIdentifier(object, level, NULL);
				break;
			case X509_OBJ_SIGNATURE:
				cert->signature = object;
				break;
			default:
				break;
		}
		objectID++;
	}
	time(&cert->installed);
	return TRUE;
}

/**
 * verify the validity of a x509 by
 * checking the notBefore and notAfter dates
 */
err_t check_validity(const private_x509_t *cert, time_t *until)
{
	time_t current_time;
	
	time(&current_time);
	
	if (cert->notAfter < *until) 
	{
		*until = cert->notAfter;
	}
	if (current_time < cert->notBefore)
	{
		return "x509 is not valid yet";
	}
	if (current_time > cert->notAfter)
	{
		return "x509 has expired";
	}
	else
	{
		return NULL;
	}
}

static rsa_public_key_t *get_public_key(private_x509_t *this)
{
	return this->public_key->clone(this->public_key);;
}

/**
 * destroy
 */
static void destroy(private_x509_t *this)
{
	free_generalNames(this->subjectAltName, FALSE);
	free_generalNames(this->crlDistributionPoints, FALSE);
	if (this->public_key)
	{
		this->public_key->destroy(this->public_key);
	}
	free(this);
}

/*
 * Described in header.
 */
x509_t *x509_create_from_chunk(chunk_t chunk)
{
	private_x509_t *this = malloc_thing(private_x509_t);
	
	/* public functions */
	this->public.equals = (bool (*) (x509_t*,x509_t*))equals;
	this->public.destroy = (void (*) (x509_t*))destroy;
	this->public.get_public_key = (rsa_public_key_t* (*) (x509_t*))get_public_key;
	
	/* initialize */
	this->subjectPublicKey = CHUNK_INITIALIZER;
	this->public_key = NULL;
	this->subjectAltName = NULL;
	this->crlDistributionPoints = NULL;
	
	if (!parse_x509cert(chunk, 0, this))
	{
		destroy(this);
		return NULL;
	}
	
	this->public_key = rsa_public_key_create_from_chunk(this->subjectPublicKey);
	if (this->public_key == NULL)
	{
		destroy(this);
		return NULL;
	}
	
	return &this->public;
}

/*
 * Described in header.
 */
x509_t *x509_create_from_file(char *filename)
{
	struct stat stb;
	FILE *file;
	char *buffer;
	chunk_t chunk;
	
	if (stat(filename, &stb) == -1)
	{
		return NULL;
	}
	
	buffer = alloca(stb.st_size);
	
	file = fopen(filename, "r");
	if (file == NULL)
	{
		return NULL;
	}
	
	if (fread(buffer, stb.st_size, 1, file) == -1) 
	{
		fclose(file);
		return NULL;
	}
	fclose(file);
	
	chunk.ptr = buffer;
	chunk.len = stb.st_size;
	
	return x509_create_from_chunk(chunk);
}
