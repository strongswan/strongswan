/*
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2002-2008 Andreas Steffen
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
 *
 * $Id$
 */

#include "x509_ac.h"
#include "ietf_attr_list.h"

#include <library.h>
#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <utils/identification.h>
#include <utils/linked_list.h>
#include <credentials/certificates/x509.h>

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
	 * X.509 attribute certificate in DER format
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
	 * Signature algorithm
	 */
	int algorithm;

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
	identification_t *authKeyIdentifier;

	/**
	 * Authority Key Serial Number
	 */
	chunk_t authKeySerialNumber;

	/**
	 * No revocation information available
	 */
	bool noRevAvail;

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

static u_char ASN1_group_oid_str[] = {
	0x06, 0x08,
		  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0a ,0x04
};

static const chunk_t ASN1_group_oid = chunk_from_buf(ASN1_group_oid_str);

static u_char ASN1_authorityKeyIdentifier_oid_str[] = {
	0x06, 0x03,
		  0x55, 0x1d, 0x23
};

static const chunk_t ASN1_authorityKeyIdentifier_oid =
	 			 	 	chunk_from_buf(ASN1_authorityKeyIdentifier_oid_str);

static u_char ASN1_noRevAvail_ext_str[] = {
	0x30, 0x09,
		  0x06, 0x03,
				0x55, 0x1d, 0x38,
		  0x04, 0x02,
				0x05, 0x00
};

static const chunk_t ASN1_noRevAvail_ext = chunk_from_buf(ASN1_noRevAvail_ext_str);

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
				timetoasn1(&this->notBefore, ASN1_GENERALIZEDTIME),
				timetoasn1(&this->notAfter,  ASN1_GENERALIZEDTIME));
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
	x509_t *x509 = (x509_t*)this->signerCert;
	identification_t *issuer = this->signerCert->get_issuer(this->signerCert);
	public_key_t *public = this->signerCert->get_public_key(this->signerCert);
	chunk_t keyIdentifier;
	chunk_t authorityCertIssuer;
	chunk_t authorityCertSerialNumber;

	if (public)
	{
		this->authKeyIdentifier = public->get_id(public, ID_PUBKEY_SHA1);
		public->destroy(public);
		keyIdentifier = this->authKeyIdentifier->get_encoding(this->authKeyIdentifier);		
	}
	else
	{
		keyIdentifier = chunk_empty;
	}

	authorityCertIssuer = build_directoryName(ASN1_CONTEXT_C_1,
								issuer->get_encoding(issuer));

	authorityCertSerialNumber = asn1_simple_object(ASN1_CONTEXT_S_2,
									x509->get_serial(x509));

	return asn1_wrap(ASN1_SEQUENCE, "cm",
				ASN1_authorityKeyIdentifier_oid,
				asn1_wrap(ASN1_OCTET_STRING, "m",
					asn1_wrap(ASN1_SEQUENCE, "mmm",
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
	return asn1_wrap(ASN1_SEQUENCE, "cmmcmmmm",
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

	DBG1("build_ac:");
	attributeCertificateInfo = build_attr_cert_info(this);

	this->signerKey->sign(this->signerKey, SIGN_RSA_EMSA_PKCS1_SHA1,
						  attributeCertificateInfo, &signatureValue);

	return asn1_wrap(ASN1_SEQUENCE, "mcm",
				attributeCertificateInfo,
				asn1_algorithmIdentifier(OID_SHA1_WITH_RSA),
				asn1_bitstring("m", signatureValue));
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
	id_match_t match;

	if (issuer->get_type(issuer) == ID_PUBKEY_SHA1)
	{
		if (this->authKeyIdentifier)
		{
			match = issuer->matches(issuer, this->authKeyIdentifier);
		}
		else
		{
			match = ID_MATCH_NONE;
		}
	}
	else
	{
		match = this->issuerName->matches(this->issuerName, issuer);
	}
	return match;
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_x509_ac_t *this, certificate_t *issuer,
					  bool sigcheck)
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
	if (this->authKeyIdentifier && key)
	{
		identification_t *subjectKeyIdentifier = key->get_id(key, ID_PUBKEY_SHA1);

		if (!subjectKeyIdentifier->equals(subjectKeyIdentifier,
										  this->authKeyIdentifier))
		{
			return FALSE;
		}
	}
	else 
	{
		if (!this->issuerName->equals(this->issuerName, issuer->get_subject(issuer)))
		{
			return FALSE;
		}
	}

	if (!sigcheck)
	{
		return TRUE;
	}
	/* TODO: generic OID to scheme mapper? */
	switch (this->algorithm)
	{
		case OID_MD5_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_MD5;
			break;
		case OID_SHA1_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
			break;
		case OID_SHA256_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA256;
			break;
		case OID_SHA384_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA384;
			break;
		case OID_SHA512_WITH_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA512;
			break;
		default:
			return FALSE;
	}
	if (key == NULL)
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
	DBG1("  attr cert from %#T is %s - existing attr_cert from %#T %s",
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
	if ((certificate_t*)this == other)
	{
		return TRUE;
	}
	if (other->equals == (void*)equals)
	{	/* same implementation */
		return chunk_equals(this->signature,
						   ((private_x509_ac_t*)other)->signature);
	}
	/* TODO: compare against other implementations */
	return FALSE;
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
		DESTROY_IF(this->authKeyIdentifier);
		DESTROY_IF(this->holderCert);
		DESTROY_IF(this->signerCert);
		DESTROY_IF(this->signerKey);
		ietfAttr_list_destroy(this->charging);
		ietfAttr_list_destroy(this->groups);
		free(this->encoding.ptr);
		free(this);
	}
}

/**
 * create an empty but initialized X.509 attribute certificate
 */
static private_x509_ac_t *create_empty()
{
	private_x509_ac_t *this = malloc_thing(private_x509_ac_t);
	
	/* public functions */
	this->public.interface.certificate.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.interface.certificate.get_subject = (identification_t* (*)(certificate_t *this))get_subject;
	this->public.interface.certificate.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.certificate.has_subject = (id_match_t(*)(certificate_t*, identification_t *subject))has_subject;
	this->public.interface.certificate.has_issuer = (id_match_t(*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.interface.certificate.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer,bool))issued_by;
	this->public.interface.certificate.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.interface.certificate.get_validity = (bool(*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.interface.certificate.get_encoding = (chunk_t(*)(certificate_t*))get_encoding;
	this->public.interface.certificate.equals = (bool(*)(certificate_t*, certificate_t *other))equals;
	this->public.interface.certificate.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.interface.certificate.destroy = (void (*)(certificate_t *this))destroy;

	/* initialize */
	this->holderIssuer = NULL;
	this->entityName = NULL;
	this->issuerName = NULL;
	this->authKeyIdentifier = NULL;
	this->holderCert = NULL;
	this->signerCert = NULL;
	this->signerKey = NULL;
	this->charging = linked_list_create();
	this->groups = linked_list_create();
	this->ref = 1;

	return this;
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for certificate loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** X.509 attribute certificate to build */
	private_x509_ac_t *ac;
};

/**
 * Implementation of builder_t.build
 */
static x509_ac_t *build(private_builder_t *this)
{
	private_x509_ac_t *ac;
	
	ac = this->ac;
	free(this);
	if (ac->holderCert && ac->signerCert && ac->signerKey)
	{
		ac->encoding = build_ac(ac);
		return &ac->public;
	}
	destroy(ac);
	return NULL;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	certificate_t *cert;

	va_start(args, part);
	switch (part)
	{
		case BUILD_NOT_BEFORE_TIME:
			this->ac->notBefore = va_arg(args, time_t);
			break;
		case BUILD_NOT_AFTER_TIME:
			this->ac->notAfter = va_arg(args, time_t);
			break;
		case BUILD_SERIAL:
			this->ac->serialNumber = va_arg(args, chunk_t);
			break;
		case BUILD_CERT:
			cert = va_arg(args, certificate_t*);
			if (cert->get_type(cert) == CERT_X509)
			{
				this->ac->holderCert = cert;
			}
			else
			{
				cert->destroy(cert);
			}
			break;
		case BUILD_SIGNING_CERT:
			cert = va_arg(args, certificate_t*);
			if (cert->get_type(cert) == CERT_X509)
			{
				this->ac->signerCert = cert;
			}
			else
			{
				cert->destroy(cert);
			}
			break;
		case BUILD_SIGNING_KEY:
			this->ac->signerKey = va_arg(args, private_key_t*);
			break;
		default:
			DBG1("ignoring unsupported build part %N", builder_part_names, part);
			break;
	}
	va_end(args);
}

/**
 * Builder construction function
 */
builder_t *x509_ac_builder(certificate_type_t type)
{
	private_builder_t *this;
	
	if (type != CERT_X509_AC)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->ac = create_empty();
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

