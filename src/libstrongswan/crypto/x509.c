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

#include <types.h>
#include <definitions.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/pem.h>
#include <utils/logger_manager.h>
#include <utils/linked_list.h>
#include <utils/identification.h>

#define CERT_WARNING_INTERVAL	30	/* days */

static logger_t *logger;

/**
 * Different kinds of generalNames
 */
typedef enum generalNames_t generalNames_t;

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
	 * Time until certificate can be trusted
	 */
	time_t until;

	/**
	 * Certificate status
	 */
	cert_status_t status;

	/**
	 * X.509 Certificate in DER format
	 */
	chunk_t certificate;

	/**
	 * X.509 certificate body over which signature is computed
	 */
	chunk_t tbsCertificate;

	/**
	 * Version of the X.509 certificate
	 */
	u_int version;
	
	/**
	 * Serial number of the X.509 certificate
	 */
	chunk_t serialNumber;

	/**
	 * Signature algorithm
	 */
	int sigAlg;
	
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
	
	/**
	 * CA basic constraints flag
	 */
	bool isCA;

	/**
	 * Signature algorithm (must be identical to sigAlg)
	 */
	int algorithm;

	/**
	 * Signature
	 */
	chunk_t signature;

	u_char authority_flags;
	chunk_t subjectPublicKey;
	bool isOcspSigner; /* ocsp */
	chunk_t accessLocation; /* ocsp */
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
static bool equals(const private_x509_t *this, const private_x509_t *other)
{
	return chunk_equals(this->signature, other->signature);
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
			logger->log(logger, CONTROL|LEVEL2, "  %s", isCA ? "TRUE" : "FALSE");
		}
		objectID++;
	}
	return isCA;
}

/*
 * extracts an otherName
 */
static bool
parse_otherName(chunk_t blob, int level0)
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
						return FALSE;
				}
				break;
			default:
				break;
		}
		objectID++;
	}
	return TRUE;
}

/*
 * extracts a generalName
 */
static identification_t *parse_generalName(chunk_t blob, int level0)
{
	asn1_ctx_t ctx;
	chunk_t object;
	int objectID = 0;
	u_int level;

	asn1_init(&ctx, blob, level0, FALSE);

	while (objectID < GN_OBJ_ROOF)
	{
		id_type_t id_type = ID_ANY;
	
		if (!extract_object(generalNameObjects, &objectID, &object, &level, &ctx))
			return NULL;

		switch (objectID)
		{
			case GN_OBJ_RFC822_NAME:
				id_type = ID_RFC822_ADDR;
				break;
			case GN_OBJ_DNS_NAME:
				id_type = ID_FQDN;
				break;
			case GN_OBJ_URI:
				id_type = ID_DER_ASN1_GN_URI;
				break;
			case GN_OBJ_DIRECTORY_NAME:
				id_type = ID_DER_ASN1_DN;
	    		break;
			case GN_OBJ_IP_ADDRESS:
				id_type = ID_IPV4_ADDR;
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

		if (id_type != ID_ANY)
		{
			identification_t *gn = identification_create_from_encoding(id_type, object);
			logger->log(logger, CONTROL|LEVEL2, "  '%s'", gn->get_string(gn));
			return gn;
        }
		objectID++;
    }
    return NULL;
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
			identification_t *gn = parse_generalName(object, level+1);

			if (gn != NULL)
				list->insert_last(list, (void *)gn);
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
								return;
							logger->log(logger, CONTROL|LEVEL2, "  '%.*s'",(int)object.len, object.ptr);
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
 * Parses an X.509v3 certificate
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
				logger->log(logger, CONTROL|LEVEL2, "  v%d", cert->version);
				break;
			case X509_OBJ_SERIAL_NUMBER:
				cert->serialNumber = object;
				break;
			case X509_OBJ_SIG_ALG:
				cert->sigAlg = parse_algorithmIdentifier(object, level, NULL);
				break;
			case X509_OBJ_ISSUER:
				cert->issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				logger->log(logger, CONTROL|LEVEL1, "  '%s'", cert->issuer->get_string(cert->issuer));
				break;
			case X509_OBJ_NOT_BEFORE:
				cert->notBefore = parse_time(object, level);
				break;
			case X509_OBJ_NOT_AFTER:
				cert->notAfter = parse_time(object, level);
				break;
			case X509_OBJ_SUBJECT:
				cert->subject = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				logger->log(logger, CONTROL|LEVEL1, "  '%s'", cert->subject->get_string(cert->subject));
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
				logger->log(logger, ERROR|LEVEL2, "  %s", critical ? "TRUE" : "FALSE");
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
							return FALSE;
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
 * Implements x509_t.is_valid
 */
static err_t is_valid(const private_x509_t *this, time_t *until)
{
	char buf[TIMETOA_BUF];

	time_t current_time = time(NULL);
	
	timetoa(buf, BUF_LEN, &this->notBefore, TRUE);
	logger->log(logger, CONTROL|LEVEL1, "  not before  : %s", buf);
	timetoa(buf, BUF_LEN, &current_time, TRUE);
	logger->log(logger, CONTROL|LEVEL1, "  current time: %s", buf);
	timetoa(buf, BUF_LEN, &this->notAfter, TRUE);
	logger->log(logger, CONTROL|LEVEL1, "  not after   : %s", buf);

	if (until != NULL
	&& (*until == UNDEFINED_TIME || this->notAfter < *until)) 
	{
		*until = this->notAfter;
	}
	if (current_time < this->notBefore)
		return "is not valid yet";
	if (current_time > this->notAfter)
		return "has expired";
	logger->log(logger, CONTROL|LEVEL1, "  certificate is valid", buf);
	return NULL;
}

/**
 * Implements x509_t.is_ca
 */
static bool is_ca(const private_x509_t *this)
{
	return this->isCA;
}

/**
 * Implements x509_t.is_self_signed
 */
static bool is_self_signed(const private_x509_t *this)
{
	return this->subject->equals(this->subject, this->issuer);
}

/**
 * Implements x509_t.equals_subjectAltName
 */
static bool equals_subjectAltName(const private_x509_t *this, identification_t *id)
{
	bool found = FALSE;
	iterator_t *iterator = this->subjectAltNames->create_iterator(this->subjectAltNames, TRUE);

	while (iterator->has_next(iterator))
	{
		identification_t *subjectAltName;

		iterator->current(iterator, (void**)&subjectAltName);
		if (id->equals(id, subjectAltName))
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implements x509_t.is_issuer
 */
static bool is_issuer(const private_x509_t *this, const private_x509_t *issuer)
{
	return (this->authKeyID.ptr)
			? chunk_equals(this->authKeyID, issuer->subjectKeyID)
			: (this->issuer->equals(this->issuer, issuer->subject)
			   && chunk_equals_or_null(this->authKeySerialNumber, issuer->serialNumber));
}

/**
 * Implements x509_t.get_certificate
 */
static chunk_t get_certificate(const private_x509_t *this)
{
	return this->certificate;
}

/**
 * Implements x509_t.get_public_key
 */
static rsa_public_key_t *get_public_key(const private_x509_t *this)
{
	return this->public_key;
}

/**
 * Implements x509_t.get_serialNumber
 */
static chunk_t get_serialNumber(const private_x509_t *this)
{
	return this->serialNumber;
}

/**
 * Implements x509_t.get_subjectKeyID
 */
static chunk_t get_subjectKeyID(const private_x509_t *this)
{
	return this->subjectKeyID;
}

/**
 * Implements x509_t.get_issuer
 */
static identification_t *get_issuer(const private_x509_t *this)
{
	return this->issuer;
}

/**
 * Implements x509_t.get_subject
 */
static identification_t *get_subject(const private_x509_t *this)
{
	return this->subject;
}

/**
 * Implements x509_t.set_until
 */
static void set_until(private_x509_t *this, time_t until)
{
	this->until = until;
}

/**
 * Implements x509_t.get_until
 */
static time_t get_until(const private_x509_t *this)
{
	return this->until;
}

/**
 * Implements x509_t.set_status
 */
static void set_status(private_x509_t *this, cert_status_t status)
{
	this->status = status;
}

/**
 * Implements x509_t.get_status
 */
static cert_status_t get_status(const private_x509_t *this)
{
	return this->status;
}

/**
 * Implements x509_t.verify
 */
static bool verify(const private_x509_t *this, const rsa_public_key_t *signer)
{
	return signer->verify_emsa_pkcs1_signature(signer, this->tbsCertificate, this->signature) == SUCCESS;
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

	while (this->crlDistributionPoints->remove_last(this->crlDistributionPoints, (void**)&id) == SUCCESS)
	{
		id->destroy(id);
	}
	this->crlDistributionPoints->destroy(this->crlDistributionPoints);

	if (this->issuer)
		this->issuer->destroy(this->issuer);

	if (this->subject)
		this->subject->destroy(this->subject);

	if (this->public_key)
		this->public_key->destroy(this->public_key);

	free(this->certificate.ptr);
	free(this);
}

/**
 * checks if the expiration date has been reached and warns during the
  * warning_interval of the imminent expiration.
  * strict=TRUE declares a fatal error, strict=FALSE issues a warning upon expiry.
 */
char* check_expiry(time_t expiration_date, int warning_interval, bool strict)
{
	int time_left;

	if (expiration_date == UNDEFINED_TIME)
	{
		return "ok (expires never)";
	}
	time_left = (expiration_date - time(NULL));
	if (time_left < 0)
	{
		return strict? "fatal (expired)" : "warning (expired)";
	}
	
	{
		static char buf[35];
		const char* unit = "second";

		if (time_left > 86400*warning_interval)
			return "ok";

		if (time_left > 172800)
		{
			time_left /= 86400;
			unit = "day";
		}
		else if (time_left > 7200)
		{
			time_left /= 3600;
			unit = "hour";
		}
		else if (time_left > 120)
		{
			time_left /= 60;
			unit = "minute";
		}
		snprintf(buf, sizeof(buf), "warning (expires in %d %s%s)", time_left, unit, (time_left == 1)?"":"s");
		
		/* TODO: This is not thread save and may result in corrupted strings. Rewrite this! */
		return buf;
	}
}

/**
 * log certificate
 */
static void log_certificate(const private_x509_t *this, logger_t *logger, bool utc, bool has_key)
{
	identification_t *subject = this->subject;
	identification_t *issuer = this->issuer;
	rsa_public_key_t *pubkey = this->public_key;

	char buf[BUF_LEN];
	char time_buf[TIMETOA_BUF];

    /* determine the current time */
    time_t now = time(NULL);

	timetoa(time_buf, TIMETOA_BUF, &this->installed, utc);
	logger->log(logger, CONTROL, "%s", time_buf);
	logger->log(logger, CONTROL, "       subject: '%s'", subject->get_string(subject));
	logger->log(logger, CONTROL, "       issuer:  '%s'", issuer->get_string(issuer));
	
	chunk_to_hex(buf, BUF_LEN, this->serialNumber);
	logger->log(logger, CONTROL, "       serial:   %s", buf);
	
	timetoa(time_buf, TIMETOA_BUF, &this->notBefore, utc);
	logger->log(logger, CONTROL, "       validity: not before %s %s", time_buf,
				(this->notBefore < now)? "ok":"fatal (not valid yet)");
	
	timetoa(time_buf, TIMETOA_BUF, &this->notAfter, utc);
	logger->log(logger, CONTROL, "                 not after  %s %s", time_buf,
			check_expiry(this->notAfter, CERT_WARNING_INTERVAL, TRUE));

	timetoa(time_buf, TIMETOA_BUF, &this->until, utc);
	switch (this->status)
	{
		case CERT_GOOD:
			snprintf(buf, BUF_LEN, " until %s", time_buf);
			break;
		case CERT_REVOKED:
			snprintf(buf, BUF_LEN, " on %s", time_buf);
			break;
		case CERT_UNKNOWN:
		case CERT_UNDEFINED:
		case CERT_UNTRUSTED:
		default:
			*buf = '\0';
	}
	logger->log(logger, CONTROL, "       pubkey:   RSA %d bits%s, status %s%s",
			BITS_PER_BYTE * pubkey->get_keysize(pubkey),
			has_key? ", has private key":"",
			enum_name(&cert_status_names, this->status), buf);

	chunk_to_hex(buf, BUF_LEN, pubkey->get_keyid(pubkey));
	logger->log(logger, CONTROL, "       keyid:    %s", buf);

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
	
	/* initialize */
	this->subjectPublicKey = CHUNK_INITIALIZER;
	this->public_key = NULL;
	this->subject = NULL;
	this->issuer = NULL;
	this->subjectAltNames = linked_list_create();
	this->crlDistributionPoints = linked_list_create();
	this->subjectKeyID = CHUNK_INITIALIZER;
	this->authKeyID = CHUNK_INITIALIZER;
	this->authKeySerialNumber = CHUNK_INITIALIZER;
	
	/* public functions */
	this->public.equals = (bool (*) (const x509_t*,const x509_t*))equals;
	this->public.equals_subjectAltName = (bool (*) (const x509_t*,identification_t*))equals_subjectAltName;
	this->public.is_issuer = (bool (*) (const x509_t*,const x509_t*))is_issuer;
	this->public.is_valid = (err_t (*) (const x509_t*,time_t*))is_valid;
	this->public.is_ca = (bool (*) (const x509_t*))is_ca;
	this->public.is_self_signed = (bool (*) (const x509_t*))is_self_signed;
	this->public.get_certificate = (chunk_t (*) (const x509_t*))get_certificate;
	this->public.get_public_key = (rsa_public_key_t* (*) (const x509_t*))get_public_key;
	this->public.get_serialNumber = (chunk_t (*) (const x509_t*))get_serialNumber;
	this->public.get_subjectKeyID = (chunk_t (*) (const x509_t*))get_subjectKeyID;
	this->public.get_issuer = (identification_t* (*) (const x509_t*))get_issuer;
	this->public.get_subject = (identification_t* (*) (const x509_t*))get_subject;
	this->public.set_until = (void (*) (x509_t*,time_t))set_until;
	this->public.get_until = (time_t (*) (const x509_t*))get_until;
	this->public.set_status = (void (*) (x509_t*,cert_status_t))set_status;
	this->public.get_status = (cert_status_t (*) (const x509_t*))get_status;
	this->public.verify = (bool (*) (const x509_t*,const rsa_public_key_t*))verify;
	this->public.destroy = (void (*) (x509_t*))destroy;
	this->public.log_certificate = (void (*) (const x509_t*,logger_t*,bool,bool))log_certificate;

	/* we do not use a per-instance logger right now, since its not always accessible */
	logger = logger_manager->get_logger(logger_manager, ASN1);
	
	if (!parse_x509cert(chunk, 0, this))
	{
		destroy(this);
		return NULL;
	}

	/* extract public key from certificate */
	this->public_key = rsa_public_key_create_from_chunk(this->subjectPublicKey);
	if (this->public_key == NULL)
	{
		destroy(this);
		return NULL;
	}
	/* set trusted lifetime of public key to notAfter */
	this->status = is_self_signed(this)? CERT_GOOD:CERT_UNDEFINED;
	this->until = this->notAfter;
	return &this->public;
}

/*
 * Described in header.
 */
x509_t *x509_create_from_file(const char *filename, const char *label)
{
	bool pgp = FALSE;
	chunk_t chunk = CHUNK_INITIALIZER;
	x509_t *cert = NULL;

	if (!pem_asn1_load_file(filename, NULL, label, &chunk, &pgp))
		return NULL;

	cert = x509_create_from_chunk(chunk);

	if (cert == NULL)
		free(chunk.ptr);
	return cert;
}
