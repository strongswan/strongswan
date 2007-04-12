/**
 * @file ac.c
 * 
 * @brief Implementation of x509ac_t.
 * 
 */

/* 
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2007 Andreas Steffen, Hochschule fuer Technik Rapperswil
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

#include <asn1/asn1.h>
#include <utils/identification.h>
#include <utils/linked_list.h>

#include "ac.h"

typedef struct private_x509ac_t private_x509ac_t;

/**
 * Private data of a x509ac_t object.
 */
struct private_x509ac_t {
	/**
	 * Public interface for this attribute certificate.
	 */
	x509ac_t public;

	/**
	 * Time when attribute certificate was installed
	 */
	time_t installed;

	/**
	 * X.509 attribute certificate in DER format
	 */
	chunk_t certificate;

	/**
	 * X.509 attribute certificate body over which signature is computed
	 */
	chunk_t certificateInfo;

	/**
	 * Version of the X.509 attribute certificate
	 */
	u_int version;

	/**
	 * Serial number of the X.509 attribute certificate
	 */
	chunk_t serialNumber;

	/**
	 * ID representing the issuer of the holder certificate
	 */
	identification_t *holderIssuer;

	/**
	 * Serial number of the holder certificate
	 */
	chunk_t holderSerial;

	/**
	 * ID representing the holder
	 */
	identification_t *entityName;
	
	/**
	 * ID representing the attribute certificate issuer
	 */
	identification_t *issuerName;

	/**
	 * Signature algorithm
	 */
	int sigAlg;

	/**
	 * Start time of certificate validity
	 */
	time_t notBefore;

	/**
	 * End time of certificate validity
	 */
	time_t notAfter;

	/**
	 * List of charging attributes
	 */
	linked_list_t *charging;

	/**
	 * List of groub attributes
	 */
	linked_list_t *groups;

	/**
	 * Authority Key Identifier
	 */
	chunk_t authKeyID;

	/**
	 * Authority Key Serial Number
	 */
	chunk_t authKeySerialNumber;

	/**
	 * No revocation information available
	 */
	bool noRevAvail;

	/**
	 * Signature algorithm (must be identical to sigAlg)
	 */
	int algorithm;

	/**
	 * Signature
	 */
	chunk_t signature;
};

/**
 * definition of ietfAttribute kinds
 */
typedef enum {
	IETF_ATTRIBUTE_OCTETS =	0,
	IETF_ATTRIBUTE_OID =	1,
	IETF_ATTRIBUTE_STRING =	2
} ietfAttribute_t;

/**
 * access structure for an ietfAttribute
 */
typedef struct ietfAttr ietfAttr_t;

struct ietfAttr {
	time_t installed;
	int count;
	ietfAttribute_t kind;
	chunk_t value;
};

/**
 * ASN.1 definition of ietfAttrSyntax
 */
static const asn1Object_t ietfAttrSyntaxObjects[] =
{
	{ 0, "ietfAttrSyntax",		ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "policyAuthority",	ASN1_CONTEXT_C_0,	ASN1_OPT |
													ASN1_BODY }, /*  1 */
	{ 1,   "end opt",			ASN1_EOC,			ASN1_END  }, /*  2 */
	{ 1,   "values",			ASN1_SEQUENCE,		ASN1_LOOP }, /*  3 */
	{ 2,     "octets",			ASN1_OCTET_STRING,	ASN1_OPT |
													ASN1_BODY }, /*  4 */
	{ 2,     "end choice",		ASN1_EOC,			ASN1_END  }, /*  5 */
	{ 2,     "oid",				ASN1_OID,			ASN1_OPT |
													ASN1_BODY }, /*  6 */
	{ 2,     "end choice",		ASN1_EOC,			ASN1_END  }, /*  7 */
	{ 2,     "string",			ASN1_UTF8STRING,	ASN1_OPT |
													ASN1_BODY }, /*  8 */
	{ 2,     "end choice",		ASN1_EOC,			ASN1_END  }, /*  9 */
	{ 1,   "end loop",			ASN1_EOC,			ASN1_END  }  /* 10 */
};

#define IETF_ATTR_OCTETS	 4
#define IETF_ATTR_OID		 6
#define IETF_ATTR_STRING	 8
#define IETF_ATTR_ROOF		11

/**
 * ASN.1 definition of roleSyntax
 */
static const asn1Object_t roleSyntaxObjects[] =
{
	{ 0, "roleSyntax",			ASN1_SEQUENCE,		ASN1_NONE }, /*  0 */
	{ 1,   "roleAuthority",		ASN1_CONTEXT_C_0,	ASN1_OPT |
													ASN1_OBJ  }, /*  1 */
	{ 1,   "end opt",			ASN1_EOC,			ASN1_END  }, /*  2 */
	{ 1,   "roleName",			ASN1_CONTEXT_C_1,	ASN1_OBJ  }  /*  3 */
};

#define ROLE_ROOF		4

/**
 * ASN.1 definition of an X509 attribute certificate
 */
static const asn1Object_t acObjects[] =
{
	{ 0, "AttributeCertificate",			ASN1_SEQUENCE,		  ASN1_OBJ  }, /*  0 */
	{ 1,   "AttributeCertificateInfo",		ASN1_SEQUENCE,		  ASN1_OBJ  }, /*  1 */
	{ 2,	   "version",					ASN1_INTEGER,		  ASN1_DEF |
																  ASN1_BODY }, /*  2 */
	{ 2,	   "holder",					ASN1_SEQUENCE,		  ASN1_NONE }, /*  3 */
	{ 3,	     "baseCertificateID",		ASN1_CONTEXT_C_0,	  ASN1_OPT  }, /*  4 */
	{ 4,	       "issuer",				ASN1_SEQUENCE,		  ASN1_OBJ  }, /*  5 */
	{ 4,	       "serial",				ASN1_INTEGER,		  ASN1_BODY }, /*  6 */
	{ 4,         "issuerUID",				ASN1_BIT_STRING,	  ASN1_OPT |
																  ASN1_BODY }, /*  7 */
	{ 4,         "end opt",					ASN1_EOC,			  ASN1_END  }, /*  8 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /*  9 */
	{ 3,	     "entityName",				ASN1_CONTEXT_C_1,	  ASN1_OPT |
																  ASN1_OBJ  }, /* 10 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 11 */
	{ 3,	     "objectDigestInfo",		ASN1_CONTEXT_C_2,	  ASN1_OPT  }, /* 12 */
	{ 4,	       "digestedObjectType",	ASN1_ENUMERATED,	  ASN1_BODY }, /* 13*/
	{ 4,	       "otherObjectTypeID",		ASN1_OID,			  ASN1_OPT |
																  ASN1_BODY }, /* 14 */
	{ 4,         "end opt",					ASN1_EOC,			  ASN1_END  }, /* 15*/
	{ 4,         "digestAlgorithm",			ASN1_EOC,			  ASN1_RAW  }, /* 16 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 17 */
	{ 2,	   "v2Form",					ASN1_CONTEXT_C_0,	  ASN1_NONE }, /* 18 */
	{ 3,	     "issuerName",				ASN1_SEQUENCE,		  ASN1_OPT |
																  ASN1_OBJ  }, /* 19 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 20 */
	{ 3,	     "baseCertificateID",		ASN1_CONTEXT_C_0,	  ASN1_OPT  }, /* 21 */
	{ 4,	       "issuerSerial",			ASN1_SEQUENCE,		  ASN1_NONE }, /* 22 */
	{ 5,	         "issuer",				ASN1_SEQUENCE,		  ASN1_OBJ  }, /* 23 */
	{ 5,	  	 "serial",					ASN1_INTEGER,		  ASN1_BODY }, /* 24 */
	{ 5,           "issuerUID",				ASN1_BIT_STRING,	  ASN1_OPT |
																  ASN1_BODY }, /* 25 */
	{ 5,           "end opt",				ASN1_EOC,			  ASN1_END  }, /* 26 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 27 */
	{ 3,       "objectDigestInfo",			ASN1_CONTEXT_C_1,	  ASN1_OPT  }, /* 28 */
	{ 4,	       "digestInfo",			ASN1_SEQUENCE,		  ASN1_OBJ  }, /* 29 */
	{ 5,  	 "digestedObjectType",			ASN1_ENUMERATED,	  ASN1_BODY }, /* 30 */
	{ 5,	  	 "otherObjectTypeID",		ASN1_OID,			  ASN1_OPT |
																  ASN1_BODY }, /* 31 */
	{ 5,           "end opt",				ASN1_EOC,			  ASN1_END  }, /* 32 */
	{ 5,           "digestAlgorithm",		ASN1_EOC,			  ASN1_RAW  }, /* 33 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 34 */
	{ 2,	   "signature",					ASN1_EOC,			  ASN1_RAW  }, /* 35 */
	{ 2,	   "serialNumber",				ASN1_INTEGER,		  ASN1_BODY }, /* 36 */
	{ 2,	   "attrCertValidityPeriod",	ASN1_SEQUENCE,		  ASN1_NONE }, /* 37 */
	{ 3,	     "notBeforeTime",			ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 38 */
	{ 3,	     "notAfterTime",			ASN1_GENERALIZEDTIME, ASN1_BODY }, /* 39 */
	{ 2,	   "attributes",				ASN1_SEQUENCE,		  ASN1_LOOP }, /* 40 */
	{ 3,       "attribute",					ASN1_SEQUENCE,		  ASN1_NONE }, /* 41 */
	{ 4,         "type",					ASN1_OID,			  ASN1_BODY }, /* 42 */
	{ 4,         "values",					ASN1_SET, 			  ASN1_LOOP }, /* 43 */
	{ 5,           "value",					ASN1_EOC, 			  ASN1_RAW  }, /* 44 */
	{ 4, 	       "end loop",				ASN1_EOC,			  ASN1_END  }, /* 45 */
	{ 2,     "end loop",					ASN1_EOC,			  ASN1_END  }, /* 46 */
	{ 2,     "extensions",					ASN1_SEQUENCE,		  ASN1_LOOP }, /* 47 */
	{ 3,       "extension",					ASN1_SEQUENCE,		  ASN1_NONE }, /* 48 */
	{ 4,         "extnID",					ASN1_OID,			  ASN1_BODY }, /* 49 */
	{ 4,         "critical",				ASN1_BOOLEAN,		  ASN1_DEF |
																  ASN1_BODY }, /* 50 */
	{ 4,         "extnValue",				ASN1_OCTET_STRING,	  ASN1_BODY }, /* 51 */
	{ 2,     "end loop",					ASN1_EOC,			  ASN1_END  }, /* 52 */
	{ 1,   "signatureAlgorithm",			ASN1_EOC,			  ASN1_RAW  }, /* 53 */
	{ 1,   "signatureValue",				ASN1_BIT_STRING,	  ASN1_BODY }  /* 54 */
};

#define AC_OBJ_CERTIFICATE			 0
#define AC_OBJ_CERTIFICATE_INFO		 1
#define AC_OBJ_VERSION				 2
#define AC_OBJ_HOLDER_ISSUER		 5
#define AC_OBJ_HOLDER_SERIAL		 6
#define AC_OBJ_ENTITY_NAME			10
#define AC_OBJ_ISSUER_NAME			19
#define AC_OBJ_ISSUER				23
#define AC_OBJ_SIG_ALG				35
#define AC_OBJ_SERIAL_NUMBER		36
#define AC_OBJ_NOT_BEFORE			38
#define AC_OBJ_NOT_AFTER			39
#define AC_OBJ_ATTRIBUTE_TYPE		42
#define AC_OBJ_ATTRIBUTE_VALUE		44
#define AC_OBJ_EXTN_ID				49
#define AC_OBJ_CRITICAL				50
#define AC_OBJ_EXTN_VALUE			51
#define AC_OBJ_ALGORITHM			53
#define AC_OBJ_SIGNATURE			54
#define AC_OBJ_ROOF					55

/**
 * Implements x509ac_t.is_valid
 */
static err_t is_valid(const private_x509ac_t *this, time_t *until)
{
	time_t current_time = time(NULL);
	
	DBG2("  not before  : %T", &this->notBefore);
	DBG2("  current time: %T", &current_time);
	DBG2("  not after   : %T", &this->notAfter);

	if (until != NULL &&
		(*until == UNDEFINED_TIME || this->notAfter < *until))
	{
		*until = this->notAfter;
	}
	if (current_time < this->notBefore)
	{
		return "is not valid yet";
	}
	if (current_time > this->notAfter)
	{
		return "has expired";
	}
	DBG2("  attribute certificate is valid");
	return NULL;
}

/**
 * Implements x509ac_t.destroy
 */
static void destroy(private_x509ac_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
x509ac_t *x509ac_create_from_chunk(chunk_t chunk)
{
	private_x509ac_t *this = malloc_thing(private_x509ac_t);
	
	/* initialize */
}

/*
 * Described in header.
 */
x509ac_t *x509ac_create_from_file(const char *filename)
{
	bool pgp = FALSE;
	chunk_t chunk = chunk_empty;
	x509ac_t *cert = NULL;

	if (!pem_asn1_load_file(filename, NULL, "attribute certificate", &chunk, &pgp))
	{
		return NULL;
	}
	cert = x509ac_create_from_chunk(chunk);

	if (cert == NULL)
	{
		free(chunk.ptr);
	}
	return cert;
}

