/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "x509_crl.h"

typedef struct private_x509_crl_t private_x509_crl_t;
typedef struct revoked_t revoked_t;

#include <time.h>

#include <debug.h>
#include <library.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <credentials/certificates/x509.h>
#include <utils/linked_list.h>

/**
 * entry for a revoked certificate
 */
struct revoked_t {
	/**
	 * serial of the revoked certificate
	 */
	chunk_t serial;

	/**
	 * date of revocation
	 */
	time_t date;

	/**
	 * reason for revocation
	 */
	crl_reason_t reason;
};

/**
 * private data of x509_crl
 */
struct private_x509_crl_t {

	/**
	 * public functions
	 */
	x509_crl_t public;

	/**
	 * X.509 crl encoding in ASN.1 DER format
	 */
	chunk_t encoding;

	/**
	 * X.509 crl body over which signature is computed
	 */
	chunk_t tbsCertList;

	/**
	 * Version of the X.509 crl
	 */
	u_int version;

	/**
	 * ID representing the crl issuer
	 */
	identification_t *issuer;

	/**
	 * CRL number
	 */
	chunk_t crlNumber;

	/**
	 * Time when the crl was generated
	 */
	time_t thisUpdate;

	/**
	 * Time when an update crl will be available
	 */
	time_t nextUpdate;

	/**
	 * list of revoked certificates as revoked_t
	 */
	linked_list_t *revoked;

	/**
	 * Authority Key Identifier
	 */
	chunk_t authKeyIdentifier;

	/**
	 * Authority Key Serial Number
	 */
	chunk_t authKeySerialNumber;

	/**
	 * Signature algorithm
	 */
	int algorithm;

	/**
	 * Signature
	 */
	chunk_t signature;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * from x509_cert
 */
extern chunk_t x509_parse_authorityKeyIdentifier(
								chunk_t blob, int level0,
								chunk_t *authKeySerialNumber);

/**
  * ASN.1 definition of an X.509 certificate revocation list
 */
static const asn1Object_t crlObjects[] = {
	{ 0, "certificateList",				ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
	{ 1,   "tbsCertList",				ASN1_SEQUENCE,     ASN1_OBJ  }, /*  1 */
	{ 2,     "version",					ASN1_INTEGER,      ASN1_OPT |
														   ASN1_BODY }, /*  2 */
	{ 2,     "end opt",					ASN1_EOC,          ASN1_END  }, /*  3 */
	{ 2,     "signature",				ASN1_EOC,          ASN1_RAW  }, /*  4 */
	{ 2,     "issuer",					ASN1_SEQUENCE,     ASN1_OBJ  }, /*  5 */
	{ 2,     "thisUpdate",				ASN1_EOC,          ASN1_RAW  }, /*  6 */
	{ 2,     "nextUpdate",				ASN1_EOC,          ASN1_RAW  }, /*  7 */
	{ 2,     "revokedCertificates",		ASN1_SEQUENCE,     ASN1_OPT |
														   ASN1_LOOP }, /*  8 */
	{ 3,       "certList",				ASN1_SEQUENCE,     ASN1_NONE }, /*  9 */
	{ 4,         "userCertificate",		ASN1_INTEGER,      ASN1_BODY }, /* 10 */
	{ 4,         "revocationDate",		ASN1_EOC,          ASN1_RAW  }, /* 11 */
	{ 4,         "crlEntryExtensions",  ASN1_SEQUENCE,     ASN1_OPT |
														   ASN1_LOOP }, /* 12 */
	{ 5,           "extension",			ASN1_SEQUENCE,	   ASN1_NONE }, /* 13 */
	{ 6,             "extnID",			ASN1_OID,          ASN1_BODY }, /* 14 */
	{ 6,             "critical",		ASN1_BOOLEAN,      ASN1_DEF |
														   ASN1_BODY }, /* 15 */
	{ 6,             "extnValue",		ASN1_OCTET_STRING, ASN1_BODY }, /* 16 */
	{ 4,         "end opt or loop",		ASN1_EOC,          ASN1_END  }, /* 17 */
	{ 2,     "end opt or loop",			ASN1_EOC,          ASN1_END  }, /* 18 */
	{ 2,     "optional extensions",		ASN1_CONTEXT_C_0,  ASN1_OPT  }, /* 19 */
	{ 3,       "crlExtensions",			ASN1_SEQUENCE,     ASN1_LOOP }, /* 20 */
	{ 4,         "extension",			ASN1_SEQUENCE,     ASN1_NONE }, /* 21 */
	{ 5,           "extnID",			ASN1_OID,          ASN1_BODY }, /* 22 */
	{ 5,           "critical",			ASN1_BOOLEAN,      ASN1_DEF |
														   ASN1_BODY }, /* 23 */
	{ 5,           "extnValue",			ASN1_OCTET_STRING, ASN1_BODY }, /* 24 */
	{ 3,       "end loop",				ASN1_EOC,          ASN1_END  }, /* 25 */
	{ 2,     "end opt",					ASN1_EOC,          ASN1_END  }, /* 26 */
	{ 1,   "signatureAlgorithm",		ASN1_EOC,          ASN1_RAW  }, /* 27 */
	{ 1,   "signatureValue",			ASN1_BIT_STRING,   ASN1_BODY }, /* 28 */
	{ 0, "exit",						ASN1_EOC,		   ASN1_EXIT }
};
#define CRL_OBJ_TBS_CERT_LIST			 1
#define CRL_OBJ_VERSION					 2
#define CRL_OBJ_SIG_ALG					 4
#define CRL_OBJ_ISSUER					 5
#define CRL_OBJ_THIS_UPDATE				 6
#define CRL_OBJ_NEXT_UPDATE				 7
#define CRL_OBJ_USER_CERTIFICATE		10
#define CRL_OBJ_REVOCATION_DATE			11
#define CRL_OBJ_CRL_ENTRY_EXTN_ID		14
#define CRL_OBJ_CRL_ENTRY_CRITICAL		15
#define CRL_OBJ_CRL_ENTRY_EXTN_VALUE	16
#define CRL_OBJ_EXTN_ID					22
#define CRL_OBJ_CRITICAL				23
#define CRL_OBJ_EXTN_VALUE				24
#define CRL_OBJ_ALGORITHM				27
#define CRL_OBJ_SIGNATURE				28

/**
 *  Parses an X.509 Certificate Revocation List (CRL)
 */
static bool parse(private_x509_crl_t *this)
{
	asn1_parser_t *parser;
	chunk_t object;
	chunk_t extnID;
	chunk_t userCertificate = chunk_empty;
	int objectID;
	int sig_alg = OID_UNKNOWN;
	bool success = FALSE;
	bool critical;
	revoked_t *revoked = NULL;

	parser = asn1_parser_create(crlObjects, this->encoding);

	while (parser->iterate(parser, &objectID, &object))
	{
		u_int level = parser->get_level(parser)+1;

		switch (objectID)
		{
			case CRL_OBJ_TBS_CERT_LIST:
				this->tbsCertList = object;
				break;
			case CRL_OBJ_VERSION:
				this->version = (object.len) ? (1+(u_int)*object.ptr) : 1;
				DBG2(DBG_LIB, "  v%d", this->version);
				break;
			case CRL_OBJ_SIG_ALG:
				sig_alg = asn1_parse_algorithmIdentifier(object, level, NULL);
				break;
			case CRL_OBJ_ISSUER:
				this->issuer = identification_create_from_encoding(ID_DER_ASN1_DN, object);
				DBG2(DBG_LIB, "  '%Y'", this->issuer);
				break;
			case CRL_OBJ_THIS_UPDATE:
				this->thisUpdate = asn1_parse_time(object, level);
				break;
			case CRL_OBJ_NEXT_UPDATE:
				this->nextUpdate = asn1_parse_time(object, level);
				break;
			case CRL_OBJ_USER_CERTIFICATE:
				userCertificate = object;
				break;
			case CRL_OBJ_REVOCATION_DATE:
				revoked = malloc_thing(revoked_t);
				revoked->serial = userCertificate;
				revoked->date = asn1_parse_time(object, level);
				revoked->reason = CRL_REASON_UNSPECIFIED;
				this->revoked->insert_last(this->revoked, (void *)revoked);
				break;
			case CRL_OBJ_CRL_ENTRY_EXTN_ID:
			case CRL_OBJ_EXTN_ID:
				extnID = object;
				break;
			case CRL_OBJ_CRL_ENTRY_CRITICAL:
			case CRL_OBJ_CRITICAL:
				critical = object.len && *object.ptr;
				DBG2(DBG_LIB, "  %s", critical ? "TRUE" : "FALSE");
				break;
			case CRL_OBJ_CRL_ENTRY_EXTN_VALUE:
			case CRL_OBJ_EXTN_VALUE:
				{
					int extn_oid = asn1_known_oid(extnID);

					if (revoked && extn_oid == OID_CRL_REASON_CODE)
					{
						if (*object.ptr == ASN1_ENUMERATED &&
							asn1_length(&object) == 1)
						{
							revoked->reason = *object.ptr;
						}
						DBG2(DBG_LIB, "  '%N'", crl_reason_names,
							 revoked->reason);
					}
					else if (extn_oid == OID_AUTHORITY_KEY_ID)
					{

						this->authKeyIdentifier = x509_parse_authorityKeyIdentifier(object,
														level, &this->authKeySerialNumber);
					}
					else if (extn_oid == OID_CRL_NUMBER)
					{
						if (!asn1_parse_simple_object(&object, ASN1_INTEGER,
													  level, "crlNumber"))
						{
							goto end;
						}
						this->crlNumber = object;
					}
				}
				break;
			case CRL_OBJ_ALGORITHM:
			{
				this->algorithm = asn1_parse_algorithmIdentifier(object, level, NULL);
				if (this->algorithm != sig_alg)
				{
					DBG1(DBG_LIB, "  signature algorithms do not agree");
					goto end;
				}
				break;
			}
			case CRL_OBJ_SIGNATURE:
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
 * enumerator filter callback for create_enumerator
 */
static bool filter(void *data, revoked_t **revoked, chunk_t *serial, void *p2,
				   time_t *date, void *p3, crl_reason_t *reason)
{
	if (serial)
	{
		*serial = (*revoked)->serial;
	}
	if (date)
	{
		*date = (*revoked)->date;
	}
	if (reason)
	{
		*reason = (*revoked)->reason;
	}
	return TRUE;
}

/**
 * Implementation of crl_t.get_serial.
 */
static chunk_t get_serial(private_x509_crl_t *this)
{
	return this->crlNumber;
}

/**
 * Implementation of crl_t.get_authKeyIdentifier.
 */
static chunk_t get_authKeyIdentifier(private_x509_crl_t *this)
{
	return this->authKeyIdentifier;
}

/**
 * Implementation of crl_t.create_enumerator.
 */
static enumerator_t* create_enumerator(private_x509_crl_t *this)
{
	return enumerator_create_filter(
								this->revoked->create_enumerator(this->revoked),
								(void*)filter, NULL, NULL);
}

/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_x509_crl_t *this)
{
	return CERT_X509_CRL;
}

/**
 * Implementation of certificate_t.get_issuer and get_subject
 */
static identification_t* get_issuer(private_x509_crl_t *this)
{
	return this->issuer;
}

/**
 * Implementation of certificate_t.has_subject and has_issuer.
 */
static id_match_t has_issuer(private_x509_crl_t *this, identification_t *issuer)
{
	if (issuer->get_type(issuer) == ID_KEY_ID && this->authKeyIdentifier.ptr &&
		chunk_equals(this->authKeyIdentifier, issuer->get_encoding(issuer)))
	{
		return ID_MATCH_PERFECT;
	}
	return this->issuer->matches(this->issuer, issuer);
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_x509_crl_t *this, certificate_t *issuer)
{
	public_key_t *key;
	signature_scheme_t scheme;
	bool valid;
	x509_t *x509 = (x509_t*)issuer;

	/* check if issuer is an X.509 CA certificate */
	if (issuer->get_type(issuer) != CERT_X509)
	{
		return FALSE;
	}
	if (!(x509->get_flags(x509) & X509_CA))
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
		if (!this->issuer->equals(this->issuer, issuer->get_subject(issuer)))
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
	valid = key->verify(key, scheme, this->tbsCertList, this->signature);
	key->destroy(key);
	return valid;
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_x509_crl_t *this)
{
	return NULL;
}

/**
 * Implementation of certificate_t.asdf
 */
static private_x509_crl_t* get_ref(private_x509_crl_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_x509_crl_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	time_t t = when ? *when : time(NULL);

	if (not_before)
	{
		*not_before = this->thisUpdate;
	}
	if (not_after)
	{
		*not_after = this->nextUpdate;
	}
	return (t <= this->nextUpdate);
}

/**
 * Implementation of certificate_t.is_newer.
 */
static bool is_newer(private_x509_crl_t *this, crl_t *that)
{
	chunk_t that_crlNumber = that->get_serial(that);
	bool new;

	/* compare crlNumbers if available - otherwise use thisUpdate */
	if (this->crlNumber.ptr != NULL && that_crlNumber.ptr != NULL)
	{
		new = chunk_compare(this->crlNumber, that_crlNumber) > 0;
		DBG1(DBG_LIB, "  crl #%#B is %s - existing crl #%#B %s",
				&this->crlNumber, new ? "newer":"not newer",
				&that_crlNumber,  new ? "replaced":"retained");
	}
	else
	{
		certificate_t *this_cert = &this->public.crl.certificate;
		certificate_t *that_cert = &that->certificate;

		time_t this_update, that_update, now = time(NULL);

		this_cert->get_validity(this_cert, &now, &this_update, NULL);
		that_cert->get_validity(that_cert, &now, &that_update, NULL);
		new = this_update > that_update;
		DBG1(DBG_LIB, "  crl from %T is %s - existing crl from %T %s",
				&this_update, FALSE, new ? "newer":"not newer",
				&that_update, FALSE, new ? "replaced":"retained");
	}
	return new;
}

/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_x509_crl_t *this)
{
	return chunk_clone(this->encoding);
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_x509_crl_t *this, certificate_t *other)
{
	chunk_t encoding;
	bool equal;

	if ((certificate_t*)this == other)
	{
		return TRUE;
	}
	if (other->equals == (void*)equals)
	{	/* skip allocation if we have the same implementation */
		return chunk_equals(this->encoding, ((private_x509_crl_t*)other)->encoding);
	}
	encoding = other->get_encoding(other);
	equal = chunk_equals(this->encoding, encoding);
	free(encoding.ptr);
	return equal;
}

/**
 * Implementation of certificate_t.destroy
 */
static void destroy(private_x509_crl_t *this)
{
	if (ref_put(&this->ref))
	{
		this->revoked->destroy_function(this->revoked, free);
		DESTROY_IF(this->issuer);
		free(this->authKeyIdentifier.ptr);
		free(this->encoding.ptr);
		free(this);
	}
}

/**
 * create an empty but initialized X.509 crl
 */
static private_x509_crl_t* create_empty(void)
{
	private_x509_crl_t *this = malloc_thing(private_x509_crl_t);

	this->public.crl.get_serial = (chunk_t (*)(crl_t*))get_serial;
	this->public.crl.get_authKeyIdentifier = (chunk_t (*)(crl_t*))get_authKeyIdentifier;
	this->public.crl.create_enumerator = (enumerator_t* (*)(crl_t*))create_enumerator;
	this->public.crl.certificate.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.crl.certificate.get_subject = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.crl.certificate.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.crl.certificate.has_subject = (id_match_t (*)(certificate_t*, identification_t *subject))has_issuer;
	this->public.crl.certificate.has_issuer = (id_match_t (*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.crl.certificate.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer))issued_by;
	this->public.crl.certificate.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.crl.certificate.get_validity = (bool (*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.crl.certificate.is_newer = (bool (*)(certificate_t*,certificate_t*))is_newer;
	this->public.crl.certificate.get_encoding = (chunk_t (*)(certificate_t*))get_encoding;
	this->public.crl.certificate.equals = (bool (*)(certificate_t*, certificate_t *other))equals;
	this->public.crl.certificate.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.crl.certificate.destroy = (void (*)(certificate_t *this))destroy;

	this->encoding = chunk_empty;
	this->tbsCertList = chunk_empty;
	this->issuer = NULL;
	this->crlNumber = chunk_empty;
	this->revoked = linked_list_create();
	this->authKeyIdentifier = chunk_empty;
	this->authKeySerialNumber = chunk_empty;
	this->ref = 1;

	return this;
}

/**
 * See header.
 */
x509_crl_t *x509_crl_load(certificate_type_t type, va_list args)
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
		private_x509_crl_t *crl = create_empty();

		crl->encoding = chunk_clone(blob);
		if (parse(crl))
		{
			return &crl->public;
		}
		destroy(crl);
	}
	return NULL;
};

