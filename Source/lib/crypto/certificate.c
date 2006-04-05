/**
 * @file certificate.c
 * 
 * @brief Implementation of certificate_t.
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

#include "certificate.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <asn1/der_decoder.h>


typedef struct private_certificate_t private_certificate_t;

/**
 * Private data of a certificate_t object.
 */
struct private_certificate_t {
	/**
	 * Public interface for this signer.
	 */
	certificate_t public;
	
	u_int version;
	
	u_int serial;
	
	chunk_t sign_alg;
	
	time_t not_before;
	
	time_t not_after;
	
	chunk_t pubkey;
	
	chunk_t pubkey_alg;
	
	bool has_issuer_uid;
	chunk_t issuer_uid;
	
	bool has_subject_uid;
	chunk_t subject_uid;
	
	chunk_t tbs_cert;
	chunk_t signature;
	
	rsa_public_key_t *public_key;
};

#define OSET(x) offsetof(private_certificate_t, x)

/**
 * Rules for de-/encoding of a certificate from/in ASN1 
 */
static asn1_rule_t certificate_rules[] = {
	{ASN1_SEQUENCE, 			0, 						0,					0					}, /* certificate */
	{ ASN1_SEQUENCE, 			ASN1_RAW,				OSET(tbs_cert),		0					}, /*  tbsCertificate */
	{  ASN1_TAG_E_0, 			ASN1_DEFAULT, 			OSET(version),		0					}, /*   EXPLICIT */
	{   ASN1_INTEGER, 			ASN1_DEFAULT,			OSET(version),		0					}, /*    version DEFAULT v1(0) */
	{  ASN1_INTEGER, 			0, 						OSET(serial),		0					}, /*   serialNumber */
	{  ASN1_SEQUENCE, 			0, 						0,					0					}, /*   signature */
	{   ASN1_OID, 				0, 						OSET(sign_alg),		0					}, /*    algorithm-oid */
	{   ASN1_NULL,				0,						0,					0					}, /*    parameters */
	{  ASN1_END, 				0, 						0,					0					}, /*   signature */
	{  ASN1_SEQUENCE,			ASN1_OF,				0,					0					}, /*   issuer */
// 	{   ASN1_SET,				ASN1_OF,				0,					0,					}, /*    RelativeDistinguishedName */
// 	{    ASN1_SEQUENCE,			0,						0,					0,					}, /*     AttributeTypeAndValue */
// 	{     ASN1_OID, 			0, 						0,					0					}, /*      AttributeType */
// 	{     ASN1_ANY, 			0, 						0,					0					}, /*      AttributeValue */
// 	{    ASN1_END, 				0, 						0,					0					}, /*     AttributeTypeAndValue */
// 	{   ASN1_END, 				0, 						0,					0					}, /*    RelativeDistinguishedName */
	{  ASN1_END, 				0, 						0,					0					}, /*   issuer */
	{  ASN1_SEQUENCE, 			0, 						0,					0					}, /*   validity */
	{   ASN1_CHOICE, 			0, 						0,					0					}, /*    notBefore */
	{     ASN1_UTCTIME, 		0, 						OSET(not_before),	0					}, /*     utcTime */
	{     ASN1_GENERALIZEDTIME, 0, 						OSET(not_before),	0					}, /*     generalTime */
	{   ASN1_END, 				0, 						0,					0					}, /*    notBefore */
	{   ASN1_CHOICE, 			0, 						0,					0					}, /*    notAfter */
	{    ASN1_UTCTIME, 			0, 						OSET(not_after),	0					}, /*     utcTime */
	{    ASN1_GENERALIZEDTIME, 	0, 						OSET(not_after),	0					}, /*     generalTime */
	{   ASN1_END, 				0, 						0,					0					}, /*    notAfter */
	{  ASN1_END, 				0, 						0,					0					}, /*   validity */
	{  ASN1_SEQUENCE, 			ASN1_OF, 				0,					0					}, /*   subject */
// 	{   ASN1_SET,				ASN1_OF,				0,					0,					}, /*    RelativeDistinguishedName */
// 	{    ASN1_SEQUENCE,			0,						0,					0,					}, /*     AttributeTypeAndValue */
// 	{     ASN1_OID, 			0, 						0,					0					}, /*      AttributeType */
// 	{     ASN1_ANY, 			0, 						0,					0					}, /*      AttributeValue */
// 	{    ASN1_END, 				0, 						0,					0					}, /*     AttributeTypeAndValue */
// 	{   ASN1_END, 				0, 						0,					0					}, /*    RelativeDistinguishedName */
	{  ASN1_END, 				0, 						0,					0					}, /*   subject */
	{  ASN1_SEQUENCE,			0,						0,					0					}, /*   subjectPublicKeyInfo */
	{   ASN1_SEQUENCE,			0, 						0,					0					}, /*    algorithm */
	{    ASN1_OID, 				0, 						OSET(pubkey_alg),	0					}, /*     algorithm-oid */
	{    ASN1_NULL,				0,						0,					0					}, /*     parameters */
	{   ASN1_END,				0,						0,					0					}, /*    algorithm */
	{   ASN1_BITSTRING, 		0, 						OSET(pubkey),		0					}, /*    subjectPublicKey */
	{  ASN1_END, 				0, 						0,					0					}, /*   subjectPublicKeyInfo */
	{  ASN1_TAG_I_1,			ASN1_OPTIONAL,			0,					OSET(has_issuer_uid)}, /*   IMPLICIT */
	{   ASN1_BITSTRING,			ASN1_OPTIONAL,			OSET(issuer_uid),	0					}, /*    issuerUniqueID OPTIONAL */
	{  ASN1_TAG_I_2,			ASN1_OPTIONAL,			0,					OSET(has_subject_uid)},/*   IMPLICIT */
	{   ASN1_BITSTRING,			ASN1_OPTIONAL,			OSET(subject_uid),	0					}, /*    subjectUniqueID OPTIONAL */
	{  ASN1_TAG_E_3,			ASN1_OPTIONAL,			0,					0					}, /*   EXPLICIT */
	{   ASN1_SEQUENCE,			ASN1_OF|ASN1_OPTIONAL,	0,					0					}, /*    extensions OPTIONAL */
// 	{    ASN1_SEQUENCE,			0,						0,					0,					}, /*     extension */
// 	{     ASN1_OID, 			0, 						0,					0					}, /*      extnID */
// 	{     ASN1_BOOLEAN,			ASN1_DEFAULT,			0,					FALSE				}, /*      critical */
// 	{     ASN1_OCTETSTRING,		0,						0,					0,					}, /*      extnValue */
// 	{    ASN1_END,				0,						0,					0,					}, /*     extension */
	{   ASN1_END,				0,						0,					0,					}, /*    extensions */
	{ ASN1_END, 				0,						0,					0					}, /*  tbsCertificate */
	{ ASN1_SEQUENCE, 			0, 						0,					0					}, /*  signatureAlgorithm */
	{  ASN1_OID, 				0, 						OSET(sign_alg),		0					}, /*   algorithm-oid */
	{  ASN1_NULL,				0,						0,					0					}, /*   parameters */
	{ ASN1_END, 				0, 						0,					0					}, /*  signatureAlgorithm */
	{ ASN1_BITSTRING,			0,						OSET(signature),	0					}, /*  signatureValue */
	{ASN1_END,					0,						0,					0					}, /* certificate */
};

/**
 * Implementation of certificate.get_public_key.
 */
static rsa_public_key_t *get_public_key(private_certificate_t *this)
{
	return this->public_key->clone(this->public_key);
}

/**
 * Implementation of certificate.destroy.
 */
static void destroy(private_certificate_t *this)
{
	this->public_key->destroy(this->public_key);
	allocator_free(this->pubkey.ptr);
	allocator_free(this->signature.ptr);
	allocator_free(this->tbs_cert.ptr);
	allocator_free(this);
}

/*
 * Described in header.
 */
certificate_t *certificate_create_from_chunk(chunk_t chunk)
{
	private_certificate_t *this = allocator_alloc_thing(private_certificate_t);
	der_decoder_t *dd;
	
	/* public functions */
	this->public.get_public_key = (rsa_public_key_t *(*) (certificate_t*))get_public_key;
	this->public.destroy = (void (*) (certificate_t*))destroy;
	
	/* initialize */
	this->pubkey = CHUNK_INITIALIZER;
	this->signature = CHUNK_INITIALIZER;
	this->tbs_cert = CHUNK_INITIALIZER;
	
	dd = der_decoder_create(certificate_rules);
	
	if (dd->decode(dd, chunk, this) != SUCCESS)
	{
		allocator_free(this);
		dd->destroy(dd);
		return NULL;
	}
	dd->destroy(dd);
	
	this->public_key = rsa_public_key_create_from_chunk(this->pubkey);
	if (this->public_key == NULL)
	{
		allocator_free(this->pubkey.ptr);
		allocator_free(this);
		return NULL;
	}
	
	return &this->public;
}

/*
 * Described in header.
 */
certificate_t *certificate_create_from_file(char *filename)
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
		return NULL;
	}
	
	chunk.ptr = buffer;
	chunk.len = stb.st_size;
	
	return certificate_create_from_chunk(chunk);
}
