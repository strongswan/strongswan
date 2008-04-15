/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2007 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen
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

#include "x509_ocsp_request.h"

#include <library.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <utils/identification.h>
#include <utils/linked_list.h>
#include <debug.h>
#include <credentials/certificates/x509.h>

#define NONCE_LEN		16

typedef struct private_x509_ocsp_request_t private_x509_ocsp_request_t;

/**
 * private data of x509_ocsp_request
 */
struct private_x509_ocsp_request_t {

	/**
	 * public functions
	 */
	x509_ocsp_request_t public;
	
	/**
	 * CA the candidates belong to
	 */
	x509_t *ca;
	
	/**
	 * Requestor name, subject of cert used if not set
	 */
	identification_t *requestor;

	/**
	 * Requestor certificate, included in request
	 */
	certificate_t *cert;
	
	/**
	 * Requestor private key to sign request
	 */
	private_key_t *key;
	
	/**
	 * list of certificates to check, x509_t
	 */
	linked_list_t *candidates;
	
	/**
	 * nonce used in request
	 */
	chunk_t nonce;
	
	/**
	 * encoded OCSP request
	 */
	chunk_t encoding;
	
	/**
	 * reference count
	 */
	refcount_t ref;
};

static u_char ASN1_nonce_oid_str[] = {
	0x06, 0x09,
		  0x2B, 0x06,
				0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
};

static u_char ASN1_response_oid_str[] = {
	0x06, 0x09,
		  0x2B, 0x06,
				0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04
};

static u_char ASN1_response_content_str[] = {
	0x04, 0x0D,
		  0x30, 0x0B,
				0x06, 0x09,
				0x2B, 0x06,
				0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
};

static const chunk_t ASN1_nonce_oid = chunk_from_buf(ASN1_nonce_oid_str);
static const chunk_t ASN1_response_oid = chunk_from_buf(ASN1_response_oid_str);
static const chunk_t ASN1_response_content = chunk_from_buf(ASN1_response_content_str);

/**
 * build requestorName
 */
static chunk_t build_requestorName(private_x509_ocsp_request_t *this)
{
	if (this->requestor || this->cert)
	{	/* use requestor name, fallback to his cert subject */
		if (!this->requestor)
		{
			this->requestor = this->cert->get_subject(this->cert);
			this->requestor = this->requestor->clone(this->requestor);
		}
		return asn1_wrap(ASN1_CONTEXT_C_1, "m",
					asn1_simple_object(ASN1_CONTEXT_C_4,
						this->requestor->get_encoding(this->requestor)));
	
	}
	return chunk_empty;
}

/**
 * build Request, not using singleRequestExtensions
 */
static chunk_t build_Request(private_x509_ocsp_request_t *this,
							 chunk_t issuerNameHash, chunk_t issuerKeyHash,
							 chunk_t serialNumber)
{
	return asn1_wrap(ASN1_SEQUENCE, "m",
				asn1_wrap(ASN1_SEQUENCE, "cmmm",
					asn1_algorithmIdentifier(OID_SHA1),
					asn1_simple_object(ASN1_OCTET_STRING, issuerNameHash),
					asn1_simple_object(ASN1_OCTET_STRING, issuerKeyHash),
					asn1_simple_object(ASN1_INTEGER, serialNumber)));
}

/**
 * build requestList
 */
static chunk_t build_requestList(private_x509_ocsp_request_t *this)
{
	chunk_t issuerNameHash, issuerKeyHash;
	identification_t *issuer;
	x509_t *x509;
	certificate_t *cert;
	chunk_t list = chunk_empty;
	public_key_t *public;
	
	cert = (certificate_t*)this->ca;
	public = cert->get_public_key(cert);
	if (public)
	{
		hasher_t *hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
		if (hasher)
		{
			identification_t *keyid = public->get_id(public, ID_PUBKEY_SHA1);	
			if (keyid)
			{
				enumerator_t *enumerator;
			
				issuerKeyHash = keyid->get_encoding(keyid);
		
				issuer = cert->get_subject(cert);
				hasher->allocate_hash(hasher, issuer->get_encoding(issuer),
									  &issuerNameHash);
				hasher->destroy(hasher);
	
				enumerator = this->candidates->create_enumerator(this->candidates);
				while (enumerator->enumerate(enumerator, &x509))
				{
					chunk_t request, serialNumber;
			
					serialNumber = x509->get_serial(x509);
					request = build_Request(this, issuerNameHash, issuerKeyHash,
											serialNumber);
					list = chunk_cat("mm", list, request);
				}
				enumerator->destroy(enumerator);
				chunk_free(&issuerNameHash);
			}
		}
		else
		{
			DBG1("creating OCSP request failed, SHA1 not supported");
		}
		public->destroy(public);
	}
	else
	{
		DBG1("creating OCSP request failed, CA certificate has no public key");
	}
	return asn1_wrap(ASN1_SEQUENCE, "m", list);
}

/**
 * build nonce extension
 */
static chunk_t build_nonce(private_x509_ocsp_request_t *this)
{
	rng_t *rng;
	
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (rng)
	{
		rng->allocate_bytes(rng, NONCE_LEN, &this->nonce);
		rng->destroy(rng);
		return asn1_wrap(ASN1_SEQUENCE, "cm", ASN1_nonce_oid,
					asn1_simple_object(ASN1_OCTET_STRING, this->nonce));
	}
	DBG1("creating OCSP request nonce failed, no RNG found");
	return chunk_empty;
}

/**
 * build acceptableResponses extension
 */
static chunk_t build_acceptableResponses(private_x509_ocsp_request_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "cc",
				ASN1_response_oid,
				ASN1_response_content);
}

/**
 * build requestExtensions
 */
static chunk_t build_requestExtensions(private_x509_ocsp_request_t *this)
{
    return asn1_wrap(ASN1_CONTEXT_C_2, "m",
				asn1_wrap(ASN1_SEQUENCE, "mm",
					build_nonce(this),
					build_acceptableResponses(this)));
}

/**
 * build tbsRequest
 */
static chunk_t build_tbsRequest(private_x509_ocsp_request_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "mmm",
				build_requestorName(this),
				build_requestList(this),
				build_requestExtensions(this));
}

/**
 * Build the optionalSignature
 */
static chunk_t build_optionalSignature(private_x509_ocsp_request_t *this,
									   chunk_t tbsRequest)
{
	int oid;
	signature_scheme_t scheme;
	chunk_t certs, signature;
	
	switch (this->key->get_type(this->key))
	{
		/* TODO: use a generic mapping function */
		case KEY_RSA:
			oid = OID_SHA1_WITH_RSA;
			scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
			break;
		default:
			DBG1("unable to sign OCSP request, %N signature not supported",
				 key_type_names, this->key->get_type(this->key));
			return chunk_empty;
	}
	
	if (!this->key->sign(this->key, scheme, tbsRequest, &signature))
	{
		DBG1("creating OCSP signature failed, skipped");
		return chunk_empty;
	}
	if (this->cert)
	{
		certs = asn1_wrap(ASN1_CONTEXT_C_0, "m",
					asn1_wrap(ASN1_SEQUENCE, "m",
						this->cert->get_encoding(this->cert)));
	}
	return asn1_wrap(ASN1_CONTEXT_C_0, "m",
				asn1_wrap(ASN1_SEQUENCE, "cmm", 
					asn1_algorithmIdentifier(oid),
					asn1_bitstring("m", signature),
					certs));
}

/**
 * Build the OCSPRequest data
 *
 */
static chunk_t build_OCSPRequest(private_x509_ocsp_request_t *this)
{
	chunk_t tbsRequest, optionalSignature = chunk_empty;
	
	tbsRequest = build_tbsRequest(this);
	if (this->key)
	{
		optionalSignature = build_optionalSignature(this, tbsRequest);
	}
	return asn1_wrap(ASN1_SEQUENCE, "mm", tbsRequest, optionalSignature);
}


/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_x509_ocsp_request_t *this)
{
	return CERT_X509_OCSP_REQUEST;
}

/**
 * Implementation of certificate_t.get_subject
 */
static identification_t* get_subject(private_x509_ocsp_request_t *this)
{
	certificate_t *ca = (certificate_t*)this->ca;
	
	if (this->requestor)
	{
		return this->requestor;
	}
	if (this->cert)
	{
		return this->cert->get_subject(this->cert);
	}
	return ca->get_subject(ca);
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_x509_ocsp_request_t *this)
{
	certificate_t *ca = (certificate_t*)this->ca;
	
	return ca->get_subject(ca);
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_subject(private_x509_ocsp_request_t *this,
							  identification_t *subject)
{
	certificate_t *current;
	enumerator_t *enumerator;
	id_match_t match, best = ID_MATCH_NONE;

	enumerator = this->candidates->create_enumerator(this->candidates);
	while (enumerator->enumerate(enumerator, &current))
	{
		match = current->has_subject(current, subject);
		if (match > best)
		{
			best = match;	
		}
	}
	enumerator->destroy(enumerator);
	return best;	
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_issuer(private_x509_ocsp_request_t *this,
							 identification_t *issuer)
{
	certificate_t *ca = (certificate_t*)this->ca;

	return ca->has_subject(ca, issuer);
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_x509_ocsp_request_t *this, certificate_t *issuer)
{
	DBG1("OCSP request validation not implemented!");
	return FALSE;
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_x509_ocsp_request_t *this)
{
	return NULL;
}

/**
 * Implementation of x509_cert_t.get_validity.
 */
static bool get_validity(private_x509_ocsp_request_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	certificate_t *cert;

	if (this->cert)
	{
		cert = this->cert;
	}
	else
	{
		cert = (certificate_t*)this->ca;
	}
	return cert->get_validity(cert, when, not_before, not_after);
}
	
/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_x509_ocsp_request_t *this)
{
	return chunk_clone(this->encoding);
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_x509_ocsp_request_t *this, certificate_t *other)
{
	chunk_t encoding;
	bool equal;
	
	if (this == (private_x509_ocsp_request_t*)other)
	{
		return TRUE;
	}
	if (other->get_type(other) != CERT_X509_OCSP_REQUEST)
	{
		return FALSE;
	}
	if (other->equals == (void*)equals)
	{	/* skip allocation if we have the same implementation */
		return chunk_equals(this->encoding, ((private_x509_ocsp_request_t*)other)->encoding); 
	}
	encoding = other->get_encoding(other);
	equal = chunk_equals(this->encoding, encoding);
	free(encoding.ptr);
	return equal;
}

/**
 * Implementation of certificate_t.asdf
 */
static private_x509_ocsp_request_t* get_ref(private_x509_ocsp_request_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of x509_ocsp_request_t.destroy
 */
static void destroy(private_x509_ocsp_request_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF((certificate_t*)this->ca);
		DESTROY_IF(this->requestor);
		DESTROY_IF(this->cert);
		DESTROY_IF(this->key);
		this->candidates->destroy_offset(this->candidates, offsetof(certificate_t, destroy));
		chunk_free(&this->nonce);
		chunk_free(&this->encoding);
		free(this);
	}
}

/**
 * create an empty but initialized OCSP request
 */
static private_x509_ocsp_request_t *create_empty()
{
	private_x509_ocsp_request_t *this = malloc_thing(private_x509_ocsp_request_t);
	
	this->public.interface.interface.get_type = (certificate_type_t (*)(certificate_t *this))get_type;
	this->public.interface.interface.get_subject = (identification_t* (*)(certificate_t *this))get_subject;
	this->public.interface.interface.get_issuer = (identification_t* (*)(certificate_t *this))get_issuer;
	this->public.interface.interface.has_subject = (id_match_t(*)(certificate_t*, identification_t *subject))has_subject;
	this->public.interface.interface.has_issuer = (id_match_t(*)(certificate_t*, identification_t *issuer))has_issuer;
	this->public.interface.interface.issued_by = (bool (*)(certificate_t *this, certificate_t *issuer))issued_by;
	this->public.interface.interface.get_public_key = (public_key_t* (*)(certificate_t *this))get_public_key;
	this->public.interface.interface.get_validity = (bool(*)(certificate_t*, time_t *when, time_t *, time_t*))get_validity;
	this->public.interface.interface.get_encoding = (chunk_t(*)(certificate_t*))get_encoding;
	this->public.interface.interface.equals = (bool(*)(certificate_t*, certificate_t *other))equals;
	this->public.interface.interface.get_ref = (certificate_t* (*)(certificate_t *this))get_ref;
	this->public.interface.interface.destroy = (void (*)(certificate_t *this))destroy;
	
	this->ca = NULL;
	this->requestor = NULL;
	this->cert = NULL;
	this->key = NULL;
	this->nonce = chunk_empty;
	this->encoding = chunk_empty;
	this->candidates = linked_list_create();
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
	/** OCSP request to build */
	private_x509_ocsp_request_t *req;
};

/**
 * Implementation of builder_t.build
 */
static x509_ocsp_request_t *build(private_builder_t *this)
{
	private_x509_ocsp_request_t *req;
	
	req = this->req;
	free(this);
	if (req->ca)
	{
		req->encoding = build_OCSPRequest(req);
		return &req->public;
	}
	destroy(req);
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
		case BUILD_CA_CERT:
			cert = va_arg(args, certificate_t*);
			if (cert->get_type(cert) == CERT_X509)
			{
				this->req->ca = (x509_t*)cert;
			}
			else
			{
				cert->destroy(cert);
			}
			break;
		case BUILD_CERT:
			cert = va_arg(args, certificate_t*);
			if (cert->get_type(cert) == CERT_X509)
			{
				this->req->candidates->insert_last(this->req->candidates, cert);
			}
			else
			{
				cert->destroy(cert);
			}
			break;
		case BUILD_SIGNING_CERT:
			this->req->cert = va_arg(args, certificate_t*);
			break;
		case BUILD_SIGNING_KEY:
			this->req->key = va_arg(args, private_key_t*);
			break;
		case BUILD_SUBJECT:
			this->req->requestor = va_arg(args, identification_t*);
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
builder_t *x509_ocsp_request_builder(certificate_type_t type)
{
	private_builder_t *this;
	
	if (type != CERT_X509_OCSP_REQUEST)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->req = create_empty();
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

