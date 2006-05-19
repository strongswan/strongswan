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

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/pem.h>
#include <utils/logger_manager.h>
#include <utils/linked_list.h>

#define BUF_LEN 512
#define BITS_PER_BYTE	8
#define RSA_MIN_OCTETS	(1024 / BITS_PER_BYTE)
#define RSA_MIN_OCTETS_UGH	"RSA modulus too small for security: less than 1024 bits"
#define RSA_MAX_OCTETS	(8192 / BITS_PER_BYTE)
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
	
	/**
	 * Time when certificate was installed
	 */
	time_t installed;

	/**
	 * X.509 Certificate in DER format
	 */
	chunk_t certificate;

	/**
	 * Version of the X.509 certificate
	 */
	u_int version;
	
	/**
	 * Serial number of the X.509 certificate
	 */
	chunk_t serialNumber;

	/**
	 * ID representing the certificate issuer
	 */
	identification_t *issuer;
	
	/**
	 * Start time of certificate validity
	 */
	time_t notBefore;

	/**
	 * End time of certificate validity
	 */
	time_t notAfter;

	/**
	 * ID representing the certificate subject
	 */
	identification_t *subject;
	
	/**
	 * List of identification_t's representing subjectAltNames
	 */
	linked_list_t *subjectAltNames;
	
	/**
	 * List of identification_t's representing issuerAltNames
	 */
	linked_list_t *issuerAltNames;
	
	/**
	 * List of identification_t's representing crlDistributionPoints
	 */
	linked_list_t *crlDistributionPoints;

	/**
	 * Subject RSA public key, if subjectPublicKeyAlgorithm == RSA
	 */
	rsa_public_key_t *public_key;
	
	/**
	 * Subject Key Identifier
	 */
	chunk_t subjectKeyID;

	/**
	 * Authority Key Identifier
	 */
	chunk_t authKeyID;

	/**
	 * Authority Key Serial Number
	 */
	chunk_t authKeySerialNumber;
	
	u_char authority_flags;
	chunk_t tbsCertificate;
	/*   signature */
	int sigAlg;
	chunk_t subjectPublicKey;
	bool isCA;
	bool isOcspSigner; /* ocsp */
	chunk_t accessLocation; /* ocsp */
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
 * ASN.1 definition of crlDistributionPoints
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
	{ 0, "x509",					ASN1_SEQUENCE,		ASN1_OBJ			}, /*  0 */
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


static u_char ASN1_subjectAltName_oid_str[] = {
	0x06, 0x03, 0x55, 0x1D, 0x11
};

static const chunk_t ASN1_subjectAltName_oid = chunk_from_buf(ASN1_subjectAltName_oid_str);


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
		memcpy(pos, gn->name.ptr, gn->name.len); 
		pos += gn->name.len;
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
 * extracts one or several GNs and puts them into a chained list
 */
static void parse_generalNames(chunk_t blob, int level0, bool implicit, linked_list_t *list)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;

	asn1_init(&ctx, blob, level0, implicit);

	while (objectID < GENERAL_NAMES_ROOF)
	{
		if (!extract_object(generalNamesObjects, &objectID, &object, &level, &ctx))
			return;
		
		if (objectID == GENERAL_NAMES_GN)
		{
			list->insert_last(list, identification_create_from_encoding(ID_DER_ASN1_GN, object));
		}
		objectID++;
	}
	return;
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
				/* TODO: parse_generalNames(object, level+1, TRUE); */
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
static void parse_crlDistributionPoints(chunk_t blob, int level0, linked_list_t *list)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	
	asn1_init(&ctx, blob, level0, FALSE);
	while (objectID < CRL_DIST_POINTS_ROOF)
	{
		if (!extract_object(crlDistributionPointsObjects, &objectID, &object, &level, &ctx))
		{
			return;
		}
		if (objectID == CRL_DIST_POINTS_FULLNAME)
		{
			/* append extracted generalNames to existing chained list */
			parse_generalNames(object, level+1, TRUE, list);

		}
		objectID++;
	}
}


/**
 * Parses an X.509v3 x509
 */
bool parse_x509cert(chunk_t blob, u_int level0, private_x509_t *cert)
{
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
				cert->certificate = object;
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
				cert->issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				break;
			case X509_OBJ_NOT_BEFORE:
				cert->notBefore = parse_time(object, level);
				break;
			case X509_OBJ_NOT_AFTER:
				cert->notAfter = parse_time(object, level);
				break;
			case X509_OBJ_SUBJECT:
				cert->subject = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				break;
			case X509_OBJ_SUBJECT_PUBLIC_KEY_ALGORITHM:
				if (parse_algorithmIdentifier(object, level, NULL) != OID_RSA_ENCRYPTION)
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
						parse_generalNames(object, level, FALSE, cert->subjectAltNames);
						break;
					case OID_BASIC_CONSTRAINTS:
						cert->isCA = parse_basicConstraints(object, level);
						break;
					case OID_CRL_DISTRIBUTION_POINTS:
						parse_crlDistributionPoints(object, level, cert->crlDistributionPoints);
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

/**
 * Implements x509_t.get_public_key
 */
static rsa_public_key_t *get_public_key(private_x509_t *this)
{
	return this->public_key->clone(this->public_key);;
}

/**
 * Implements x509_t.get_subject
 */
static identification_t *get_subject(private_x509_t *this)
{
	return this->subject;
}

/**
 * Implements x509_t.get_issuer
 */
static identification_t *get_issuer(private_x509_t *this)
{
	return this->issuer;
}

/**
 * destroy
 */
static void destroy(private_x509_t *this)
{
	identification_t *id;
	while (this->subjectAltNames->remove_last(this->subjectAltNames, (void**)&id) == SUCCESS)
	{
		id->destroy(id);
	}
	this->subjectAltNames->destroy(this->subjectAltNames);
	while (this->issuerAltNames->remove_last(this->issuerAltNames, (void**)&id) == SUCCESS)
	{
		id->destroy(id);
	}
	this->issuerAltNames->destroy(this->issuerAltNames);
	while (this->crlDistributionPoints->remove_last(this->crlDistributionPoints, (void**)&id) == SUCCESS)
	{
		id->destroy(id);
	}
	this->crlDistributionPoints->destroy(this->crlDistributionPoints);
	if (this->issuer)
	{
		this->issuer->destroy(this->issuer);
	}
	if (this->subject)
	{
		this->subject->destroy(this->subject);
	}
	if (this->public_key)
	{
		this->public_key->destroy(this->public_key);
	}
	free(this->certificate.ptr);
	free(this);
}

/**
 * log certificate
 */
static void log_certificate(private_x509_t *this, logger_t *logger, bool utc)
{
	identification_t *subject = this->subject;
	identification_t *issuer = this->issuer;

	rsa_public_key_t *rsa_key = this->public_key;

	char buf[BUF_LEN];

	timetoa(buf, BUF_LEN, &this->installed, utc);
	logger->log(logger, CONTROL, "%s", buf);
	logger->log(logger, CONTROL, "       subject: '%s'", subject->get_string(subject));
	logger->log(logger, CONTROL, "       issuer:  '%s'", issuer->get_string(issuer));
	chunk_to_hex(buf, BUF_LEN, this->serialNumber);
	logger->log(logger, CONTROL, "       serial:   %s", buf);
	timetoa(buf, BUF_LEN, &this->notBefore, utc);
	logger->log(logger, CONTROL, "       validity: not before %s", buf);
	timetoa(buf, BUF_LEN, &this->notAfter, utc);
	logger->log(logger, CONTROL, "                 not after  %s", buf);
	logger->log(logger, CONTROL, "       pubkey:   RSA %d bits", BITS_PER_BYTE * rsa_key->get_keysize(rsa_key));
	if (this->subjectKeyID.ptr != NULL)
	{
		chunk_to_hex(buf, BUF_LEN, this->subjectKeyID);
		logger->log(logger, CONTROL, "       subjkey:  %s", buf);
	}
	if (this->authKeyID.ptr != NULL)
	{
		chunk_to_hex(buf, BUF_LEN, this->authKeyID);
		logger->log(logger, CONTROL, "       authkey:  %s", buf);
	}
	if (this->authKeySerialNumber.ptr != NULL)
	{
		chunk_to_hex(buf, BUF_LEN, this->authKeySerialNumber);
		logger->log(logger, CONTROL, "       aserial:  %s", buf);
	}
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
	this->public.get_subject = (identification_t* (*) (x509_t*))get_subject;
	this->public.get_issuer = (identification_t* (*) (x509_t*))get_issuer;
	this->public.log_certificate = (void (*) (x509_t*,logger_t*,bool))log_certificate;
	
	/* initialize */
	this->subjectPublicKey = CHUNK_INITIALIZER;
	this->public_key = NULL;
	this->subject = NULL;
	this->issuer = NULL;
	this->subjectAltNames = linked_list_create();
	this->issuerAltNames = linked_list_create();
	this->crlDistributionPoints = linked_list_create();
	
	/* we do not use a per-instance logger right now, since its not always accessible */
	logger = logger_manager->get_logger(logger_manager, ASN1);
	
	if (!is_asn1(chunk) ||
		!parse_x509cert(chunk, 0, this))
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
x509_t *x509_create_from_file(const char *filename)
{
	bool pgp = FALSE;
	chunk_t chunk = CHUNK_INITIALIZER;
	x509_t *cert = NULL;

	if (!pem_asn1_load_file(filename, "", "certificate", &chunk, &pgp))
		return NULL;

	cert = x509_create_from_chunk(chunk);
	if (cert == NULL)
	{
		free(chunk.ptr);
	}
	return cert;
}
