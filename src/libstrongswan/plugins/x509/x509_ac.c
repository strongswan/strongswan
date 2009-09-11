/*
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2002-2008 Andreas Steffen
 * Copyright (C) 2009 Martin Willi
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
 */

#include "x509_ac.h"
#include "ietf_attr_list.h"

#include <time.h>

#include <library.h>
#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <utils/identification.h>
#include <utils/linked_list.h>
#include <credentials/certificates/x509.h>
#include <credentials/keys/private_key.h>

extern chunk_t x509_parse_authorityKeyIdentifier(chunk_t blob,
									int level0, chunk_t *authKeySerialNumber);

typedef struct private_x509_ac_t private_x509_ac_t;

/**
 * private data of x509_ac_t object
 */
struct private_x509_ac_t {

	/**
	 * public functions
	 */
	x509_ac_t public;

	/**
	 * X.509 attribute certificate encoding in ASN.1 DER format
	 */
	chunk_t encoding;

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
	chunk_t authKeyIdentifier;

	/**
	 * Authority Key Serial Number
	 */
	chunk_t authKeySerialNumber;

	/**
	 * No revocation information available
	 */
	bool noRevAvail;

	/**
	 * Signature algorithm
	 */
	int algorithm;

	/**
	 * Signature
	 */
	chunk_t signature;

	/**
	 * Holder certificate
	 */
	certificate_t *holderCert;

	/**
	 * Signer certificate
	 */
	certificate_t *signerCert;

	/**
	* Signer private key;
	*/
	private_key_t *signerKey;

	/**
	 * reference count
	 */
	refcount_t ref;
};

static chunk_t ASN1_group_oid = chunk_from_chars(
	0x06, 0x08,
		  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0a ,0x04
);
static chunk_t ASN1_authorityKeyIdentifier_oid = chunk_from_chars(
	0x06, 0x03,
		  0x55, 0x1d, 0x23
);
static chunk_t ASN1_noRevAvail_ext = chunk_from_chars(
	0x30, 0x09,
		  0x06, 0x03,
				0x55, 0x1d, 0x38,
		  0x04, 0x02,
				0x05, 0x00
);

/**
 * declaration of function implemented in x509_cert.c
 */
extern void x509_parse_generalNames(chunk_t blob, int level0, bool implicit,
									linked_list_t *list);
/**
 * parses a directoryName
 */
static bool parse_directoryName(chunk_t blob, int level, bool implicit, identification_t **name)
{
	bool has_directoryName;
	linked_list_t *list = linked_list_create();

	x509_parse_generalNames(blob, level, implicit, list);
	has_directoryName = list->get_count(list) > 0;

	if (has_directoryName)
	{
		iterator_t *iterator = list->create_iterator(list, TRUE);
		identification_t *directoryName;
		bool first = TRUE;

		while (iterator->iterate(iterator, (void**)&directoryName))
		{
			if (first)
			{
				*name = directoryName;
				first = FALSE;
			}
			else
			{
				DBG1("more than one directory name - first selected");
				directoryName->destroy(directoryName);
			}
		}
		iterator->destroy(iterator);
	}
	else
	{
		DBG1("no directoryName found");
	}

	list->destroy(list);
	return has_directoryName;
}

/**
 * ASN.1 definition of roleSyntax
 */
static const asn1Object_t roleSyntaxObjects[] =
{
	{ 0, "roleSyntax",		ASN1_SEQUENCE,		ASN1_NONE }, /* 0 */
	{ 1,   "roleAuthority",	ASN1_CONTEXT_C_0,	ASN1_OPT |
												ASN1_OBJ  }, /* 1 */
	{ 1,   "end opt",		ASN1_EOC,			ASN1_END  }, /* 2 */
	{ 1,   "roleName",		ASN1_CONTEXT_C_1,	ASN1_OBJ  }, /* 3 */
	{ 0, "exit",			ASN1_EOC,			ASN1_EXIT }
};

/**
 * Parses roleSyntax
 */
static void parse_roleSyntax(chunk_t blob, int level0)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;

	parser = asn1_parser_create(roleSyntaxObjects, blob);
	parser->set_top_level(parser, level0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			default:
				break;
		}
	}
	parser->destroy(parser);
}

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
	{ 3,	   "entityName",				ASN1_CONTEXT_C_1,	  ASN1_OPT |
																  ASN1_OBJ  }, /* 10 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 11 */
	{ 3,	     "objectDigestInfo",		ASN1_CONTEXT_C_2,	  ASN1_OPT  }, /* 12 */
	{ 4,	       "digestedObjectType",	ASN1_ENUMERATED,	  ASN1_BODY }, /* 13 */
	{ 4,	       "otherObjectTypeID",		ASN1_OID,			  ASN1_OPT |
																  ASN1_BODY }, /* 14 */
	{ 4,         "end opt",					ASN1_EOC,			  ASN1_END  }, /* 15 */
	{ 4,         "digestAlgorithm",			ASN1_EOC,			  ASN1_RAW  }, /* 16 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 17 */
	{ 2,	   "v2Form",					ASN1_CONTEXT_C_0,	  ASN1_NONE }, /* 18 */
	{ 3,	     "issuerName",				ASN1_SEQUENCE,		  ASN1_OPT |
																  ASN1_OBJ  }, /* 19 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 20 */
	{ 3,	     "baseCertificateID",		ASN1_CONTEXT_C_0,	  ASN1_OPT  }, /* 21 */
	{ 4,	       "issuerSerial",			ASN1_SEQUENCE,		  ASN1_NONE }, /* 22 */
	{ 5,	         "issuer",				ASN1_SEQUENCE,		  ASN1_OBJ  }, /* 23 */
	{ 5,		 "serial",					ASN1_INTEGER,		  ASN1_BODY }, /* 24 */
	{ 5,           "issuerUID",				ASN1_BIT_STRING,	  ASN1_OPT |
																  ASN1_BODY }, /* 25 */
	{ 5,           "end opt",				ASN1_EOC,			  ASN1_END  }, /* 26 */
	{ 3,       "end opt",					ASN1_EOC,			  ASN1_END  }, /* 27 */
	{ 3,       "objectDigestInfo",			ASN1_CONTEXT_C_1,	  ASN1_OPT  }, /* 28 */
	{ 4,	       "digestInfo",			ASN1_SEQUENCE,		  ASN1_OBJ  }, /* 29 */
	{ 5,  	 "digestedObjectType",			ASN1_ENUMERATED,	  ASN1_BODY }, /* 30 */
	{ 5,		 "otherObjectTypeID",		ASN1_OID,			  ASN1_OPT |
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
	{ 1,   "signatureValue",				ASN1_BIT_STRING,	  ASN1_BODY }, /* 54 */
	{ 0, "exit",							ASN1_EOC,			  ASN1_EXIT }
};
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

/**
 * Parses an X.509 attribute certificate
 */
static bool parse_certificate(private_x509_ac_t *this)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	int type     = OID_UNKNOWN;
	int extn_oid = OID_UNKNOWN;
	int sig_alg  = OID_UNKNOWN;
	bool success = FALSE;
	bool critical;

	parser = asn1_parser_create(acObjects, this->encoding);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser)+1;

		switch (objectID)
		{
			case AC_OBJ_CERTIFICATE_INFO:
				this->certificateInfo = object;
				break;
			case AC_OBJ_VERSION:
				this->version = (object.len) ? (1 + (u_int)*object.ptr) : 1;
				DBG2("  v%d", this->version);
				if (this->version != 2)
				{
					DBG1("v%d attribute certificates are not supported", this->version);
					goto end;
				}
				break;
			case AC_OBJ_HOLDER_ISSUER:
				if (!parse_directoryName(object, level, FALSE, &this->holderIssuer))
				{
					goto end;
				}
				break;
			case AC_OBJ_HOLDER_SERIAL:
				this->holderSerial = object;
				break;
			case AC_OBJ_ENTITY_NAME:
				if (!parse_directoryName(object, level, TRUE, &this->entityName))
				{
					goto end;
				}
				break;
			case AC_OBJ_ISSUER_NAME:
				if (!parse_directoryName(object, level, FALSE, &this->issuerName))
				{
					goto end;
				}
				break;
			case AC_OBJ_SIG_ALG:
				sig_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case AC_OBJ_SERIAL_NUMBER:
				this->serialNumber = chunk_clone(object);
				break;
			case AC_OBJ_NOT_BEFORE:
				this->notBefore = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
				break;
			case AC_OBJ_NOT_AFTER:
				this->notAfter = asn1_to_time(&object, ASN1_GENERALIZEDTIME);
				break;
			case AC_OBJ_ATTRIBUTE_TYPE:
				type = asn1_known_oid(object);
				break;
			case AC_OBJ_ATTRIBUTE_VALUE:
			{
				switch (type)
				{
					case OID_AUTHENTICATION_INFO:
						DBG2("  need to parse authenticationInfo");
						break;
					case OID_ACCESS_IDENTITY:
						DBG2("  need to parse accessIdentity");
						break;
					case OID_CHARGING_IDENTITY:
						ietfAttr_list_create_from_chunk(object, this->charging, level);
						break;
					case OID_GROUP:
						ietfAttr_list_create_from_chunk(object, this->groups, level);
						break;
					case OID_ROLE:
						parse_roleSyntax(object, level);
						break;
					default:
						break;
				}
				break;
			}
			case AC_OBJ_EXTN_ID:
				extn_oid = asn1_known_oid(object);
				break;
			case AC_OBJ_CRITICAL:
				critical = object.len && *object.ptr;
				DBG2("  %s",(critical)?"TRUE":"FALSE");
				break;
			case AC_OBJ_EXTN_VALUE:
			{
				switch (extn_oid)
				{
					case OID_CRL_DISTRIBUTION_POINTS:
						DBG2("  need to parse crlDistributionPoints");
						break;
					case OID_AUTHORITY_KEY_ID:
						this->authKeyIdentifier = x509_parse_authorityKeyIdentifier(object,
													level, &this->authKeySerialNumber);
						break;
					case OID_TARGET_INFORMATION:
						DBG2("  need to parse targetInformation");
						break;
					case OID_NO_REV_AVAIL:
						this->noRevAvail = TRUE;
						break;
					default:
						break;
				}
				break;
			}
			case AC_OBJ_ALGORITHM:
				this->algorithm = asn1_parse_algorithmIdentifier(object, level,
																 NULL);
				if (this->algorithm != sig_alg)
				{
					DBG1("  signature algorithms do not agree");
					success = FALSE;
					goto end;
				}
				break;
			case AC_OBJ_SIGNATURE:
				this->signature = object;
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
 * build directoryName
 */
static chunk_t build_directoryName(asn1_t tag, chunk_t name)
{
	return asn1_wrap(tag, "m",
		asn1_simple_object(ASN1_CONTEXT_C_4, name));
}

/**
 * build holder
 */
static chunk_t build_holder(private_x509_ac_t *this)
{
	x509_t* x509 = (x509_t*)this->holderCert;
	identification_t *issuer = this->holderCert->get_issuer(this->holderCert);
	identification_t *subject = this->holderCert->get_subject(this->holderCert);

	return asn1_wrap(ASN1_SEQUENCE, "mm",
		asn1_wrap(ASN1_CONTEXT_C_0, "mm",
			build_directoryName(ASN1_SEQUENCE, issuer->get_encoding(issuer)),
			asn1_simple_object(ASN1_INTEGER, x509->get_serial(x509))
		),
		build_directoryName(ASN1_CONTEXT_C_1, subject->get_encoding(subject)));
}

/**
 * build v2Form
 */
static chunk_t build_v2_form(private_x509_ac_t *this)
{
	identification_t *subject = this->signerCert->get_subject(this->signerCert);

	return asn1_wrap(ASN1_CONTEXT_C_0, "m",
		build_directoryName(ASN1_SEQUENCE, subject->get_encoding(subject)));
}

/**
 * build attrCertValidityPeriod
 */
static chunk_t build_attr_cert_validity(private_x509_ac_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "mm",
				asn1_from_time(&this->notBefore, ASN1_GENERALIZEDTIME),
				asn1_from_time(&this->notAfter,  ASN1_GENERALIZEDTIME));
}


/**
 * build attribute type
 */
static chunk_t build_attribute_type(const chunk_t type, chunk_t content)
{
	return asn1_wrap(ASN1_SEQUENCE, "cm",
				type,
				asn1_wrap(ASN1_SET, "m", content));
}

/**
 * build attributes
 */
static chunk_t build_attributes(private_x509_ac_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "m",
		build_attribute_type(ASN1_group_oid, ietfAttr_list_encode(this->groups)));
}

/**
 * build authorityKeyIdentifier
 */
static chunk_t build_authorityKeyIdentifier(private_x509_ac_t *this)
{
	chunk_t keyIdentifier = chunk_empty;
	chunk_t authorityCertIssuer;
	chunk_t authorityCertSerialNumber;
	identification_t *issuer;
	public_key_t *public;
	x509_t *x509;

	x509 = (x509_t*)this->signerCert;
	issuer = this->signerCert->get_issuer(this->signerCert);
	public = this->signerCert->get_public_key(this->signerCert);
	if (public)
	{
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &keyIdentifier))
		{
			this->authKeyIdentifier = chunk_clone(keyIdentifier);
		}
		public->destroy(public);
	}
	authorityCertIssuer = build_directoryName(ASN1_CONTEXT_C_1,
											issuer->get_encoding(issuer));
	authorityCertSerialNumber = asn1_simple_object(ASN1_CONTEXT_S_2,
											x509->get_serial(x509));
	return asn1_wrap(ASN1_SEQUENCE, "cm",
				ASN1_authorityKeyIdentifier_oid,
				asn1_wrap(ASN1_OCTET_STRING, "m",
					asn1_wrap(ASN1_SEQUENCE, "cmm",
						keyIdentifier,
						authorityCertIssuer,
						authorityCertSerialNumber
					)
				)
		   );
}

/**
 * build extensions
 */
static chunk_t build_extensions(private_x509_ac_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "mc",
				build_authorityKeyIdentifier(this),
				ASN1_noRevAvail_ext);
}

/**
 * build attributeCertificateInfo
 */
static chunk_t build_attr_cert_info(private_x509_ac_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "cmmmmmmm",
				ASN1_INTEGER_1,
				build_holder(this),
				build_v2_form(this),
				asn1_algorithmIdentifier(OID_SHA1_WITH_RSA),
				asn1_simple_object(ASN1_INTEGER, this->serialNumber),
				build_attr_cert_validity(this),
				build_attributes(this),
				build_extensions(this));
}


/**
 * build an X.509 attribute certificate
 */
static chunk_t build_ac(private_x509_ac_t *this)
{
	chunk_t signatureValue;
	chunk_t attributeCertificateInfo;

	attributeCertificateInfo = build_attr_cert_info(this);

	this->signerKey->sign(this->signerKey, SIGN_RSA_EMSA_PKCS1_SHA1,
						  attributeCertificateInfo, &signatureValue);

	return asn1_wrap(ASN1_SEQUENCE, "mmm",
				attributeCertificateInfo,
				asn1_algorithmIdentifier(OID_SHA1_WITH_RSA),
				asn1_bitstring("m", signatureValue));
}

/**
 * Implementation of ac_t.get_serial.
 */
static chunk_t get_serial(private_x509_ac_t *this)
{
	return this->serialNumber;
}

/**
 * Implementation of ac_t.get_holderSerial.
 */
static chunk_t get_holderSerial(private_x509_ac_t *this)
{
	return this->holderSerial;
}

/**
 * Implementation of ac_t.get_holderIssuer.
 */
static identification_t* get_holderIssuer(private_x509_ac_t *this)
{
	return this->holderIssuer;
}

/**
 * Implementation of ac_t.get_authKeyIdentifier.
 */
static chunk_t get_authKeyIdentifier(private_x509_ac_t *this)
{
	return this->authKeyIdentifier;
}

/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_x509_ac_t *this)
{
	return CERT_X509_AC;
}

/**
 * Implementation of certificate_t.get_subject
 */
static identification_t* get_subject(private_x509_ac_t *this)
{
	return this->entityName;
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_x509_ac_t *this)
{
	return this->issuerName;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_subject(private_x509_ac_t *this, identification_t *subject)
{
	return ID_MATCH_NONE;
}

/**
 * Implementation of certificate_t.has_issuer.
 */
static id_match_t has_issuer(private_x509_ac_t *this, identification_t *issuer)
{
	if (issuer->get_type(issuer) == ID_KEY_ID && this->authKeyIdentifier.ptr &&
		chunk_equals(this->authKeyIdentifier, issuer->get_encoding(issuer)))
	{
		return ID_MATCH_PERFECT;
	}
	return this->issuerName->matches(this->issuerName, issuer);
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_x509_ac_t *this, certificate_t *issuer)
{
	public_key_t *key;
	signature_scheme_t scheme;
	bool valid;
	x509_t *x509 = (x509_t*)issuer;

	/* check if issuer is an X.509 AA certificate */
	if (issuer->get_type(issuer) != CERT_X509)
	{
		return FALSE;
	}
	if (!(x509->get_flags(x509) & X509_AA))
	{
		return FALSE;
	}

	/* get the public key of the issuer */
	key = issuer->get_public_key(issuer);

	/* compare keyIdentifiers if available, otherwise use DNs */
	if (this->authKeyIdentifier.ptr && key)
	{
		chunk_t fingerprint;

		if (!key->get_fingerprint(key, KEY_ID_PUBKEY_SHA1, &fingerprint) ||
			!chunk_equals(fingerprint, this->authKeyIdentifier))
		{
			return FALSE;
		}
	}
	else
	{
		if (!this->issuerName->equals(this->issuerName,
									  issuer->get_subject(issuer)))
		{
			return FALSE;
		}
	}

	/* determine signature scheme */
	scheme = signature_scheme_from_oid(this->algorithm);

	if (scheme == SIGN_UNKNOWN || key == NULL)
	{
		return FALSE;
	}
	valid = key->verify(key, scheme, this->certificateInfo, this->signature);
	key->destroy(key);
	return valid;
}

/**
 * Implementation of certificate_t.get_public_key.
 */
static public_key_t* get_public_key(private_x509_ac_t *this)
{
	return NULL;
}

/**
 * Implementation of certificate_t.get_ref.
 */
static private_x509_ac_t* get_ref(private_x509_ac_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_x509_ac_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	time_t t;

	if (when)
	{
		t = *when;
	}
	else
	{
		t = time(NULL);
	}
	if (not_before)
	{
		*not_before = this->notBefore;
	}
	if (not_after)
	{
		*not_after = this->notAfter;
	}
	return (t >= this->notBefore && t <= this->notAfter);
}

/**
 * Implementation of certificate_t.is_newer.
 */
static bool is_newer(private_x509_ac_t *this, ac_t *that)
{
	certificate_t *this_cert = &this->public.interface.certificate;
	certificate_t *that_cert = &that->certificate;
	time_t this_update, that_update, now = time(NULL);
	bool new;

	this_cert->get_validity(this_cert, &now, &this_update, NULL);
	that_cert->get_validity(that_cert, &now, &that_update, NULL);
	new = this_update > that_update;
	DBG1("  attr cert from %T is %s - existing attr_cert from %T %s",
			&this_update, FALSE, new ? "newer":"not newer",
			&that_update, FALSE, new ? "replaced":"retained");
	return new;
}

/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_x509_ac_t *this)
{
	return chunk_clone(this->encoding);
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_x509_ac_t *this, certificate_t *other)
{
	chunk_t encoding;
	bool equal;

	if ((certificate_t*)this == other)
	{
		return TRUE;
	}
	if (other->equals == (void*)equals)
	{	/* skip allocation if we have the same implementation */
		return chunk_equals(this->encoding, ((private_x509_ac_t*)other)->encoding);
	}
	encoding = other->get_encoding(other);
	equal = chunk_equals(this->encoding, encoding);
	free(encoding.ptr);
	return equal;
}

/**
 * Implementation of x509_ac_t.destroy
 */
static void destroy(private_x509_ac_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->holderIssuer);
		DESTROY_IF(this->entityName);
		DESTROY_IF(this->issuerName);
		DESTROY_IF(this->holderCert);
		DESTROY_IF(this->signerCert);
		DESTROY_IF(this->signerKey);

		ietfAttr_list_destroy(this->charging);
		ietfAttr_list_destroy(this->groups);
		free(this->serialNumber.ptr);
		free(this->authKeyIdentifier.ptr);
		free(this->encoding.ptr);
		free(this);
	}
}

/**
 * create an empty but initialized X.509 attribute certificate
 */
static private_x509_ac_t *create_empty(void)
{
	private_x509_ac_t *this = malloc_thing(private_x509_ac_t);

	/* public functions */
	this->public.interface.get_serial = (chunk_t (*)(ac_t*))get_serial;
	this->public.interface.get_holderSerial = (chunk_t (*)(ac_t*))get_holderSerial;
	this->public.interface.get_holderIssuer = (identification_t* (*)(ac_t*))get_holderIssuer;
	this->public.interface.get_authKeyIdentifier = (chunk_t(*)(ac_t*))get_authKeyIdentifier;
	this->public.interface.certificate.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.interface.certificate.get_subject = (identification_t* (*)(certificate_t *this))get_subject;
	this->public.interface.certificate.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.certificate.has_subject = (id_match_t(*)(certificate_t*, identification_t *subject))has_subject;
	this->public.interface.certificate.has_issuer = (id_match_t(*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.interface.certificate.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer))issued_by;
	this->public.interface.certificate.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.interface.certificate.get_validity = (bool(*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.interface.certificate.is_newer = (bool (*)(certificate_t*,certificate_t*))is_newer;
	this->public.interface.certificate.get_encoding = (chunk_t(*)(certificate_t*))get_encoding;
	this->public.interface.certificate.equals = (bool(*)(certificate_t*, certificate_t *other))equals;
	this->public.interface.certificate.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.interface.certificate.destroy = (void (*)(certificate_t *this))destroy;

	/* initialize */
	this->encoding = chunk_empty;
	this->serialNumber = chunk_empty;
	this->holderSerial = chunk_empty;
	this->authKeyIdentifier = chunk_empty;
	this->holderIssuer = NULL;
	this->entityName = NULL;
	this->issuerName = NULL;
	this->holderCert = NULL;
	this->signerCert = NULL;
	this->signerKey = NULL;
	this->charging = linked_list_create();
	this->groups = linked_list_create();
	this->ref = 1;

	return this;
}

/**
 * See header.
 */
x509_ac_t *x509_ac_load(certificate_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (blob.ptr)
	{
		private_x509_ac_t *ac = create_empty();

		ac->encoding = chunk_clone(blob);
		if (parse_certificate(ac))
		{
			return &ac->public;
		}
		destroy(ac);
	}
	return NULL;
}

/**
 * See header.
 */
x509_ac_t *x509_ac_gen(certificate_type_t type, va_list args)
{
	private_x509_ac_t *ac;

	ac = create_empty();
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_NOT_BEFORE_TIME:
				ac->notBefore = va_arg(args, time_t);
				continue;
			case BUILD_NOT_AFTER_TIME:
				ac->notAfter = va_arg(args, time_t);
				continue;
			case BUILD_SERIAL:
				ac->serialNumber = chunk_clone(va_arg(args, chunk_t));
				continue;
			case BUILD_IETF_GROUP_ATTR:
				ietfAttr_list_create_from_string(va_arg(args, char*), ac->groups);
				continue;
			case BUILD_CERT:
				ac->holderCert = va_arg(args, certificate_t*);
				ac->holderCert->get_ref(ac->holderCert);
				continue;
			case BUILD_SIGNING_CERT:
				ac->signerCert = va_arg(args, certificate_t*);
				ac->signerCert->get_ref(ac->signerCert);
				continue;
			case BUILD_SIGNING_KEY:
				ac->signerKey = va_arg(args, private_key_t*);
				ac->signerKey->get_ref(ac->signerKey);
				continue;
			case BUILD_END:
				break;
			default:
				destroy(ac);
				return NULL;
		}
		break;
	}

	if (ac->signerKey && ac->holderCert && ac->signerCert &&
		ac->holderCert->get_type(ac->holderCert) == CERT_X509 &&
		ac->signerCert->get_type(ac->signerCert) == CERT_X509)
	{
		ac->encoding = build_ac(ac);
		return &ac->public;
	}
	destroy(ac);
	return NULL;
}

