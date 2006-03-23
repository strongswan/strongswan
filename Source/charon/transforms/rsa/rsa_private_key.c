/**
 * @file rsa_private_key.c
 * 
 * @brief Implementation of rsa_private_key_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "rsa_private_key.h"

#include <daemon.h>
#include <utils/allocator.h>


/* 
 * Oids for hash algorithms are defined in
 * rsa_public_key.c.
 */
extern u_int8_t md2_oid[18];
extern u_int8_t md5_oid[18];
extern u_int8_t sha1_oid[15];
extern u_int8_t sha256_oid[19];
extern u_int8_t sha384_oid[19];
extern u_int8_t sha512_oid[19];

/*
asn1_module_t rsa_private_key_module = {
	{ASN1_SEQUENCE, 0, 0, 0},
	{	ASN1_INTEGER, 0, 		offsetof(private_rsa_private_key, version), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, n), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, e), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, d), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, p), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, q), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, exp1), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, exp2), 0},
	{	ASN1_INTEGER, ASN1_MPZ, offsetof(private_rsa_private_key, coeff), 0},
	{ASN1_END, 0, 0, 0},
};*/

/**
 *  Public exponent to use for key generation.
 */
#define PUBLIC_EXPONENT 0x10001


typedef struct private_rsa_private_key_t private_rsa_private_key_t;

/**
 * Private data of a rsa_private_key_t object.
 */
struct private_rsa_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	rsa_private_key_t public;
	
	/**
	 * Version of key, as encoded in PKCS#1
	 */
	u_int version;
	
	/**
	 * Is the key already set ?
	 */
	bool is_key_set;
	
	/**
	 * Public modulus.
	 */
	mpz_t n;
	
	/**
	 * Public exponent.
	 */
	mpz_t e;
	
	/**
	 * Private prime 1.
	 */
	mpz_t p;
	
	/**
	 * Private Prime 2.
	 */
	mpz_t q;
	
	/**
	 * Private exponent.
	 */
	mpz_t d;
	
	/**
	 * Private exponent 1.
	 */
	mpz_t exp1;
	
	/**
	 * Private exponent 2.
	 */
	mpz_t exp2;
	
	/**
	 * Private coefficient.
	 */
	mpz_t coeff;
	
	/**
	 * Keysize in bytes.
	 */
	size_t k;
	
	/**
	 * @brief Implements the RSADP algorithm specified in PKCS#1.
	 * 
	 * @param this		calling object
	 * @param data		data to process
	 * @return			processed data
	 */
	chunk_t (*rsadp) (private_rsa_private_key_t *this, chunk_t data);
		
	/**
	 * @brief Implements the RSASP1 algorithm specified in PKCS#1.
	 * @param this		calling object
	 * @param data		data to process
	 * @return			processed data
	 */
	chunk_t (*rsasp1) (private_rsa_private_key_t *this, chunk_t data);
	
	/**
	 * @brief Generate a prime value.
	 * 
	 * @param this		calling object
	 * @param prime_size size of the prime, in bytes
	 * @param[out] prime uninitialized mpz
	 */
	void (*compute_prime) (private_rsa_private_key_t *this, size_t prime_size, mpz_t *prime);
	
};

/**
 * Implementation of private_rsa_private_key_t.compute_prime.
 */
static void compute_prime(private_rsa_private_key_t *this, size_t prime_size, mpz_t *prime)
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
 * Implementation of private_rsa_private_key_t.rsadp and private_rsa_private_key_t.rsasp1.
 */
static chunk_t rsadp(private_rsa_private_key_t *this, chunk_t data)
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
 * Implementation of rsa_private_key.build_emsa_signature.
 */
static status_t build_emsa_pkcs1_signature(private_rsa_private_key_t *this, hash_algorithm_t hash_algorithm, chunk_t data, chunk_t *signature)
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
 * Implementation of rsa_private_key.set_key.
 */
static status_t set_key(private_rsa_private_key_t *this, chunk_t key)
{
	chunk_t n, e, p, q, d, exp1, exp2, coeff;
	this->k = key.len / 8;
	
	n.len = this->k;
	e.len = this->k;
	p.len = this->k;
	q.len = this->k;
	d.len = this->k;
	exp1.len = this->k;
	exp2.len = this->k;
	coeff.len = this->k;
	
	n.ptr = key.ptr + this->k * 0;
	e.ptr = key.ptr + this->k * 1;
	p.ptr = key.ptr + this->k * 2;
	q.ptr = key.ptr + this->k * 3;
	d.ptr = key.ptr + this->k * 4;
	exp1.ptr = key.ptr + this->k * 5;
	exp2.ptr = key.ptr + this->k * 6;
	coeff.ptr = key.ptr + this->k * 7;
	
	mpz_init(this->n);
	mpz_init(this->e);
	mpz_init(this->p);
	mpz_init(this->q);
	mpz_init(this->d);
	mpz_init(this->exp1);
	mpz_init(this->exp2);
	mpz_init(this->coeff);
	
	mpz_import(this->n, this->k, 1, 1, 1, 0, n.ptr);
	mpz_import(this->e, this->k, 1, 1, 1, 0, e.ptr);
	mpz_import(this->p, this->k, 1, 1, 1, 0, p.ptr);
	mpz_import(this->q, this->k, 1, 1, 1, 0, q.ptr);
	mpz_import(this->d, this->k, 1, 1, 1, 0, d.ptr);
	mpz_import(this->exp1, this->k, 1, 1, 1, 0, exp1.ptr);
	mpz_import(this->exp2, this->k, 1, 1, 1, 0, exp2.ptr);
	mpz_import(this->coeff, this->k, 1, 1, 1, 0, coeff.ptr);
	
	this->is_key_set = TRUE;
	
	return SUCCESS;

}
	
/**
 * Implementation of rsa_private_key.get_key.
 */
static status_t get_key(private_rsa_private_key_t *this, chunk_t *key)
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
 * Implementation of rsa_private_key.load_key.
 */
static status_t load_key(private_rsa_private_key_t *this, char *file)
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of rsa_private_key.save_key.
 */
static status_t save_key(private_rsa_private_key_t *this, char *file)
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of rsa_private_key.generate_key.
 */
static status_t generate_key(private_rsa_private_key_t *this, size_t key_size)
{
	mpz_t p, q, n, e, d, exp1, exp2, coeff;
	mpz_t m, q1, t;
	
	if (key_size < 0) 
	{
		return INVALID_ARG;
	}
	
	if (this->is_key_set)
	{
		mpz_clear(this->n);
		mpz_clear(this->e);
		mpz_clear(this->p);
		mpz_clear(this->q);
		mpz_clear(this->d);
		mpz_clear(this->exp1);
		mpz_clear(this->exp2);
		mpz_clear(this->coeff);
	}
	
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
 * Implementation of rsa_private_key.get_public_key.
 */
rsa_public_key_t *get_public_key(private_rsa_private_key_t *this)
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
 * Implementation of rsa_private_key.destroy.
 */
static void destroy(private_rsa_private_key_t *this)
{
	if (this->is_key_set)
	{
		mpz_clear(this->n);
		mpz_clear(this->e);
		mpz_clear(this->p);
		mpz_clear(this->q);
		mpz_clear(this->d);
		mpz_clear(this->exp1);
		mpz_clear(this->exp2);
		mpz_clear(this->coeff);
	}
	allocator_free(this);
}

/*
 * Described in header.
 */
rsa_private_key_t *rsa_private_key_create(hash_algorithm_t hash_algoritm)
{
	private_rsa_private_key_t *this = allocator_alloc_thing(private_rsa_private_key_t);
	
	/* public functions */
	this->public.build_emsa_pkcs1_signature = (status_t (*) (rsa_private_key_t*,hash_algorithm_t,chunk_t,chunk_t*))build_emsa_pkcs1_signature;
	this->public.set_key = (status_t (*) (rsa_private_key_t*,chunk_t))set_key;
	this->public.get_key = (status_t (*) (rsa_private_key_t*,chunk_t*))get_key;
	this->public.load_key = (status_t (*) (rsa_private_key_t*,char*))load_key;
	this->public.save_key = (status_t (*) (rsa_private_key_t*,char*))save_key;
	this->public.generate_key = (status_t (*) (rsa_private_key_t*,size_t))generate_key;
	this->public.get_public_key = (rsa_public_key_t *(*) (rsa_private_key_t*))get_public_key;
	this->public.destroy = (void (*) (rsa_private_key_t*))destroy;
	
	/* private functions */
	this->rsadp = rsadp;
	this->rsasp1 = rsadp; /* same algorithm */
	this->compute_prime = compute_prime;
	
	this->is_key_set = FALSE;
	
	return &(this->public);
}
