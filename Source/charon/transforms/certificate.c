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
};

#define OSET(x) offsetof(private_certiciate_t, x)

/**
 * Rules for de-/encoding of a certificate from/in ASN1 
 */
static asn1_rule_t certificate_rules[] = {
	{ASN1_SEQUENCE, 			0, 				0,					0					}, /* certificate */
	{ ASN1_SEQUENCE, 			0, 				0,					0					}, /*  tbsCertificate */
	{  ASN1_TAG_E_0, 			ASN1_DEFAULT, 	OSET(version),		0					}, /*   EXPLICIT version DEFAULT v1(0) */
	{   ASN1_INTEGER, 			0,				OSET(version),		0					},
	{  ASN1_INTEGER, 			0, 				OSET(serial),		0					}, /*  serialNumber */
	{  ASN1_SEQUENCE, 			0, 				0,					0					}, /*  signature */
	{   ASN1_OID, 				0, 				OSET(sign_alg),		0					}, /*   algorithm */
	{  ASN1_END, 				0, 				0,					0					}, /*  signature */
	{  ASN1_CHOICE, 			0, 				0,					0					}, /*  issuer */
	{   ASN1_SEQUENCE, 			ASN1_OF, 		0,					0					},
	/* name */
	{   ASN1_END, 				0, 				0,					0					},
	{  ASN1_END, 				0, 				0,					0					}, /*  issuer */
	{  ASN1_SEQUENCE, 			0, 				0,					0					}, /*  validity */
	{   ASN1_CHOICE, 			0, 				0,					0					}, /*   notBefore */
	{    ASN1_UTCTIME, 			0, 				OSET(not_before),	0					}, /*    utcTime */
	{    ASN1_GENERALIZEDTIME, 	0, 				OSET(not_before),	0					}, /*    generalTime */
	{   ASN1_END, 				0, 				0,					0					}, /*   notBefore */
	{   ASN1_CHOICE, 			0, 				0,					0					}, /*   notAfter */
	{    ASN1_UTCTIME, 			0, 				OSET(not_after),	0					}, /*    utcTime */
	{    ASN1_GENERALIZEDTIME, 	0, 				OSET(not_after),	0					}, /*    generalTime */
	{   ASN1_END, 				0, 				0,					0					}, /*   notAfter */
	{  ASN1_END, 				0, 				0,					0					}, /*  validity */
	{  ASN1_CHOICE, 			0, 				0,					0					}, /*  subject */
	{   ASN1_SEQUENCE, 			ASN1_OF, 		0,					0					},
	/* name */
	{   ASN1_END, 				0, 				0,					0					},
	{  ASN1_END, 				0, 				0,					0					}, /*  subject */
	{  ASN1_SEQUENCE, 			0, 				0,					0					}, /*  subjectPublicKeyInfo */
	{   ASN1_OID, 				0, 				OSET(pubkey_alg),	0					}, /*   algorithm */
	{   ASN1_BITSTRING, 		0, 				OSET(pubkey),		0					}, /*   subjectPublicKey */
	{  ASN1_END, 				0, 				0,					0					}, /*  subjectPublicKeyInfo */
	{  ASN1_TAG_I_1,			ASN1_OPTIONAL,	0,					OSET(has_issuer_uid)}, /*  IMPLICIT issuerUniqueID OPTIONAL */
	{   ASN1_BITSTRING,			0,				OSET(issuer_uid),	0					},
	{  ASN1_TAG_I_2,			ASN1_OPTIONAL,	0,					OSET(has_subject_uid)},/*  IMPLICIT subjectUniqueID OPTIONAL */
	{   ASN1_BITSTRING,			0,				OSET(subject_uid),	0					},
	{  ASN1_TAG_E_3,			ASN1_OPTIONAL,	0,					0					}, /*  EXPLICIT extensions OPTIONAL*/
	{   ASN1_SEQUENCE,			ASN1_OF,		0,					0					},
	/* extension */
	{   ASN1_END				0,				0,					0,					}, /*  extensions */
	{ ASN1_END, 				0, 				0,					0					}, /* certificate */
};

/**
 * Implementation of private_certificate_t.compute_prime.
 */
static void compute_prime(private_certificate_t *this, size_t prime_size, mpz_t *prime)
{
	randomizer_t *randomizer;
	chunk_t random_bytes;
	
	randomizer = randomizer_create();
	mpz_init(*prime);
	
	do
	{
		randomizer->allocate_random_bytes(randomizer, prime_size, &random_bytes);
		
		/* make sure most significant bit is set */
		random_bytes.ptr[0] = random_bytes.ptr[0] | 0x80;
		
		/* convert chunk to mpz value */
		mpz_import(*prime, random_bytes.len, 1, 1, 1, 0, random_bytes.ptr);
		
		/* get next prime */
		mpz_nextprime (*prime, *prime);
		
		allocator_free(random_bytes.ptr);
	}
	/* check if it isnt too large */
	while (((mpz_sizeinbase(*prime, 2) + 7) / 8) > prime_size);
	
	randomizer->destroy(randomizer);
}

/**
 * Implementation of private_certificate_t.rsadp and private_certificate_t.rsasp1.
 */
static chunk_t rsadp(private_certificate_t *this, chunk_t data)
{
	mpz_t t1, t2;
	chunk_t decrypted;
	
	mpz_init(t1);
	mpz_init(t2);
	
	mpz_import(t1, data.len, 1, 1, 1, 0, data.ptr);
	
	mpz_powm(t2, t1, this->exp1, this->p);	/* m1 = c^dP mod p */
	mpz_powm(t1, t1, this->exp2, this->q);	/* m2 = c^dQ mod Q */
	mpz_sub(t2, t2, t1);					/* h = qInv (m1 - m2) mod p */
	mpz_mod(t2, t2, this->p);
	mpz_mul(t2, t2, this->coeff);
	mpz_mod(t2, t2, this->p);
	
	mpz_mul(t2, t2, this->q);				/* m = m2 + h q */
	mpz_add(t1, t1, t2);
	
	decrypted.len = this->k;
	decrypted.ptr = mpz_export(NULL, NULL, 1, decrypted.len, 1, 0, t1);
	
	mpz_clear(t1);
	mpz_clear(t2);
	
	return decrypted;
}

/**
 * Implementation of certificate.build_emsa_signature.
 */
static status_t build_emsa_pkcs1_signature(private_certificate_t *this, hash_algorithm_t hash_algorithm, chunk_t data, chunk_t *signature)
{
	hasher_t *hasher;
	chunk_t hash;
	chunk_t oid;
	chunk_t em;
	
	/* get oid string prepended to hash */
	switch (hash_algorithm)
	{	
		case HASH_MD2:
		{
			oid.ptr = md2_oid;
			oid.len = sizeof(md2_oid);
			break;
		}
		case HASH_MD5:
		{
			oid.ptr = md5_oid;
			oid.len = sizeof(md5_oid);
			break;
		}
		case HASH_SHA1:
		{
			oid.ptr = sha1_oid;
			oid.len = sizeof(sha1_oid);
			break;
		}
		case HASH_SHA256:
		{
			oid.ptr = sha256_oid;
			oid.len = sizeof(sha256_oid);
			break;
		}
		case HASH_SHA384:
		{
			oid.ptr = sha384_oid;
			oid.len = sizeof(sha384_oid);
			break;
		}
		case HASH_SHA512:
		{
			oid.ptr = sha512_oid;
			oid.len = sizeof(sha512_oid);
			break;
		}
		default:
		{
			return NOT_SUPPORTED;	
		}
	}
	
	/* get hasher */
	hasher = hasher_create(hash_algorithm);
	if (hasher == NULL)
	{
		return NOT_SUPPORTED;	
	}
	
	/* build hash */
	hasher->allocate_hash(hasher, data, &hash);
	hasher->destroy(hasher);
	
	/* build chunk to rsa-decrypt:
	 * EM = 0x00 || 0x01 || PS || 0x00 || T. 
	 * PS = 0xFF padding, with length to fill em
	 * T = oid || hash
	 */
	em.len = this->k;
	em.ptr = allocator_alloc(em.len);
	
	/* fill em with padding */
	memset(em.ptr, 0xFF, em.len);
	/* set magic bytes */
	*(em.ptr) = 0x00;
	*(em.ptr+1) = 0x01;
	*(em.ptr + em.len - hash.len - oid.len - 1) = 0x00;
	/* set hash */
	memcpy(em.ptr + em.len - hash.len, hash.ptr, hash.len);
	/* set oid */
	memcpy(em.ptr + em.len - hash.len - oid.len, oid.ptr, oid.len);

	
	/* build signature */
	*signature = this->rsasp1(this, em);
	
	allocator_free(hash.ptr);
	allocator_free(em.ptr);
	
	return SUCCESS;	
}

	
/**
 * Implementation of certificate.set_key.
 */
static status_t set_key(private_certificate_t *this, chunk_t key)
{
	der_decoder_t *dd;
	status_t status;
	
	dd = der_decoder_create(certificate_rules);
	
	status = dd->decode(dd, key, this);
	if (status == SUCCESS)
	{
		this->is_key_set = TRUE;
		this->k = mpz_sizeinbase(this->n, 2) / 8;
	}
	dd->destroy(dd);
	return status;
}

/**
 * Implementation of certificate.get_key.
 */
static status_t get_key(private_certificate_t *this, chunk_t *key)
{
	if (!this->is_key_set)
	{
		return INVALID_STATE;	
	}
	
	chunk_t n, e, p, q, d, exp1, exp2, coeff;

	n.len = this->k;
	n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, this->n);
	e.len = this->k;
	e.ptr = mpz_export(NULL, NULL, 1, e.len, 1, 0, this->e);
	p.len = this->k;
	p.ptr = mpz_export(NULL, NULL, 1, p.len, 1, 0, this->p);
	q.len = this->k;
	q.ptr = mpz_export(NULL, NULL, 1, q.len, 1, 0, this->q);
	d.len = this->k;
	d.ptr = mpz_export(NULL, NULL, 1, d.len, 1, 0, this->d);
	exp1.len = this->k;
	exp1.ptr = mpz_export(NULL, NULL, 1, exp1.len, 1, 0, this->exp1);
	exp2.len = this->k;
	exp2.ptr = mpz_export(NULL, NULL, 1, exp2.len, 1, 0, this->exp2);
	coeff.len = this->k;
	coeff.ptr = mpz_export(NULL, NULL, 1, coeff.len, 1, 0, this->coeff);
	
	key->len = this->k * 8;
	key->ptr = allocator_alloc(key->len);
	memcpy(key->ptr + this->k * 0, n.ptr , n.len);
	memcpy(key->ptr + this->k * 1, e.ptr, e.len);
	memcpy(key->ptr + this->k * 2, p.ptr, p.len);
	memcpy(key->ptr + this->k * 3, q.ptr, q.len);
	memcpy(key->ptr + this->k * 4, d.ptr, d.len);
	memcpy(key->ptr + this->k * 5, exp1.ptr, exp1.len);
	memcpy(key->ptr + this->k * 6, exp2.ptr, exp2.len);
	memcpy(key->ptr + this->k * 7, coeff.ptr, coeff.len);
	
	allocator_free(n.ptr);
	allocator_free(e.ptr);
	allocator_free(p.ptr);
	allocator_free(q.ptr);
	allocator_free(d.ptr);
	allocator_free(exp1.ptr);
	allocator_free(exp2.ptr);
	allocator_free(coeff.ptr);
	
	return SUCCESS;
}
	
/**
 * Implementation of certificate.load_key.
 */
static status_t load_key(private_certificate_t *this, char *file)
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of certificate.save_key.
 */
static status_t save_key(private_certificate_t *this, char *file)
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of certificate.generate_key.
 */
static status_t generate_key(private_certificate_t *this, size_t key_size)
{
	mpz_t p, q, n, e, d, exp1, exp2, coeff;
	mpz_t m, q1, t;
	
	if (key_size < 0) 
	{
		return INVALID_ARG;
	}
	
	mpz_clear(this->n);
	mpz_clear(this->e);
	mpz_clear(this->p);
	mpz_clear(this->q);
	mpz_clear(this->d);
	mpz_clear(this->exp1);
	mpz_clear(this->exp2);
	mpz_clear(this->coeff);
	
	key_size = key_size / 8;
	
	mpz_init(t);	
	mpz_init(n);
	mpz_init(d);
	mpz_init(exp1);
	mpz_init(exp2);
	mpz_init(coeff);
	
	/* Get values of primes p and q  */
	this->compute_prime(this, key_size/2, &p);
	this->compute_prime(this, key_size/2, &q);

	/* Swapping Primes so p is larger then q */
	if (mpz_cmp(p, q) < 0)
	{
		mpz_set(t, p);
		mpz_set(p, q);
		mpz_set(q, t);
	}
	
	mpz_mul(n, p, q);						/* n = p*q */
	mpz_init_set_ui(e, PUBLIC_EXPONENT);	/* assign public exponent */
	mpz_init_set(m, p); 					/* m = p */
	mpz_sub_ui(m, m, 1);					/* m = m -1 */
	mpz_init_set(q1, q);					/* q1 = q */
	mpz_sub_ui(q1, q1, 1);					/* q1 = q1 -1 */
	mpz_gcd(t, m, q1);						/* t = gcd(p-1, q-1) */
	mpz_mul(m, m, q1);						/* m = (p-1)*(q-1) */
	mpz_divexact(m, m, t);					/* m = m / t */
	mpz_gcd(t, m, e);						/* t = gcd(m, e) (greatest common divisor) */

	mpz_invert(d, e, m);					/* e has an inverse mod m */
	if (mpz_cmp_ui(d, 0) < 0)				/* make sure d is positive */
	{
		mpz_add(d, d, m);
	}
	mpz_sub_ui(t, p, 1);					/* t = p-1 */
	mpz_mod(exp1, d, t);					/* exp1 = d mod p-1 */
	mpz_sub_ui(t, q, 1);					/* t = q-1 */
	mpz_mod(exp2, d, t);					/* exp2 = d mod q-1 */
	
	mpz_invert(coeff, q, p);				/* coeff = q^-1 mod p */
	if (mpz_cmp_ui(coeff, 0) < 0)			/* make coeff d is positive */
	{
		mpz_add(coeff, coeff, p);
	}

	mpz_clear(q1);
	mpz_clear(m);
	mpz_clear(t);

	/* apply values */
	*(this->p) = *p;
	*(this->q) = *q;
	*(this->n) = *n;
	*(this->e) = *e;
	*(this->d) = *d;
	*(this->exp1) = *exp1;
	*(this->exp2) = *exp2;
	*(this->coeff) = *coeff;
	
	/* set key size in bytes */
	
	this->is_key_set = TRUE;
	this->k = key_size;
	
	return SUCCESS;
}

/**
 * Implementation of certificate.get_public_key.
 */
rsa_public_key_t *get_public_key(private_certificate_t *this)
{
	rsa_public_key_t *public_key;
	//chunk_t key;
	
	public_key = rsa_public_key_create();
	
	if (this->is_key_set)
	{	
	
		chunk_t n, e, key;

		n.len = this->k;
		n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, this->n);
		e.len = this->k;
		e.ptr = mpz_export(NULL, NULL, 1, e.len, 1, 0, this->e);
		
		key.len = this->k * 2;
		key.ptr = allocator_alloc(key.len);
		memcpy(key.ptr, n.ptr, n.len);
		memcpy(key.ptr + n.len, e.ptr, e.len);
		allocator_free(n.ptr);
		allocator_free(e.ptr);
		
		public_key->set_key(public_key, key);
		allocator_free(key.ptr);

	}
	
	return public_key;
}


/**
 * Implementation of certificate.destroy.
 */
static void destroy(private_certificate_t *this)
{
	mpz_clear(this->n);
	mpz_clear(this->e);
	mpz_clear(this->p);
	mpz_clear(this->q);
	mpz_clear(this->d);
	mpz_clear(this->exp1);
	mpz_clear(this->exp2);
	mpz_clear(this->coeff);
	allocator_free(this);
}

/*
 * Described in header.
 */
certificate_t *certificate_create(hash_algorithm_t hash_algoritm)
{
	private_certificate_t *this = allocator_alloc_thing(private_certificate_t);
	
	/* public functions */
	this->public.build_emsa_pkcs1_signature = (status_t (*) (certificate_t*,hash_algorithm_t,chunk_t,chunk_t*))build_emsa_pkcs1_signature;
	this->public.set_key = (status_t (*) (certificate_t*,chunk_t))set_key;
	this->public.get_key = (status_t (*) (certificate_t*,chunk_t*))get_key;
	this->public.load_key = (status_t (*) (certificate_t*,char*))load_key;
	this->public.save_key = (status_t (*) (certificate_t*,char*))save_key;
	this->public.generate_key = (status_t (*) (certificate_t*,size_t))generate_key;
	this->public.get_public_key = (rsa_public_key_t *(*) (certificate_t*))get_public_key;
	this->public.destroy = (void (*) (certificate_t*))destroy;
	
	/* private functions */
	this->rsadp = rsadp;
	this->rsasp1 = rsadp; /* same algorithm */
	this->compute_prime = compute_prime;
	
	mpz_init(this->n);
	mpz_init(this->e);
	mpz_init(this->p);
	mpz_init(this->q);
	mpz_init(this->d);
	mpz_init(this->exp1);
	mpz_init(this->exp2);
	mpz_init(this->coeff);
	this->is_key_set = FALSE;
	
	return &(this->public);
}
