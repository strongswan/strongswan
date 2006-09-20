/**
 * @file rsa_private_key.c
 * 
 * @brief Implementation of rsa_private_key_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "rsa_public_key.h"
#include "rsa_private_key.h"

#include <asn1/asn1.h>
#include <asn1/pem.h>
#include <utils/randomizer.h>

/**
 * OIDs for hash algorithms are defined in rsa_public_key.c.
 */
extern u_int8_t md2_oid[18];
extern u_int8_t md5_oid[18];
extern u_int8_t sha1_oid[15];
extern u_int8_t sha256_oid[19];
extern u_int8_t sha384_oid[19];
extern u_int8_t sha512_oid[19];


/**
 * defined in rsa_public_key.c
 */
extern chunk_t rsa_public_key_info_to_asn1(const mpz_t n, const mpz_t e);


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
	 * Keyid formed as a SHA-1 hash of a publicKeyInfo object
	 */
	chunk_t keyid;

	
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
	status_t (*compute_prime) (private_rsa_private_key_t *this, size_t prime_size, mpz_t *prime);
	
};

/* ASN.1 definition of a PKCS#1 RSA private key */
static const asn1Object_t privkey_objects[] = {
	{ 0, "RSAPrivateKey",		ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
	{ 1,   "version",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
	{ 1,   "modulus",			ASN1_INTEGER,      ASN1_BODY }, /*  2 */
	{ 1,   "publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  3 */
	{ 1,   "privateExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  4 */
	{ 1,   "prime1",			ASN1_INTEGER,      ASN1_BODY }, /*  5 */
	{ 1,   "prime2",			ASN1_INTEGER,      ASN1_BODY }, /*  6 */
	{ 1,   "exponent1",			ASN1_INTEGER,      ASN1_BODY }, /*  7 */
	{ 1,   "exponent2",			ASN1_INTEGER,      ASN1_BODY }, /*  8 */
	{ 1,   "coefficient",		ASN1_INTEGER,      ASN1_BODY }, /*  9 */
	{ 1,   "otherPrimeInfos",	ASN1_SEQUENCE,     ASN1_OPT |
												   ASN1_LOOP }, /* 10 */
	{ 2,     "otherPrimeInfo",	ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
	{ 3,       "prime",			ASN1_INTEGER,      ASN1_BODY }, /* 12 */
	{ 3,       "exponent",		ASN1_INTEGER,      ASN1_BODY }, /* 13 */
	{ 3,       "coefficient",	ASN1_INTEGER,      ASN1_BODY }, /* 14 */
	{ 1,   "end opt or loop",	ASN1_EOC,          ASN1_END  }  /* 15 */
};

#define PRIV_KEY_VERSION		 1
#define PRIV_KEY_MODULUS		 2
#define PRIV_KEY_PUB_EXP		 3
#define PRIV_KEY_PRIV_EXP		 4
#define PRIV_KEY_PRIME1			 5
#define PRIV_KEY_PRIME2			 6
#define PRIV_KEY_EXP1			 7
#define PRIV_KEY_EXP2			 8
#define PRIV_KEY_COEFF			 9
#define PRIV_KEY_ROOF			16

static private_rsa_private_key_t *rsa_private_key_create_empty(void);

/**
 * Implementation of private_rsa_private_key_t.compute_prime.
 */
static status_t compute_prime(private_rsa_private_key_t *this, size_t prime_size, mpz_t *prime)
{
	randomizer_t *randomizer;
	chunk_t random_bytes;
	status_t status;
	
	randomizer = randomizer_create();
	mpz_init(*prime);
	
	do
	{
		status = randomizer->allocate_random_bytes(randomizer, prime_size, &random_bytes);
		if (status != SUCCESS)
		{
			randomizer->destroy(randomizer);
			mpz_clear(*prime);
			return FAILED;
		}
		
		/* make sure most significant bit is set */
		random_bytes.ptr[0] = random_bytes.ptr[0] | 0x80;
		
		/* convert chunk to mpz value */
		mpz_import(*prime, random_bytes.len, 1, 1, 1, 0, random_bytes.ptr);
		
		/* get next prime */
		mpz_nextprime (*prime, *prime);
		
		free(random_bytes.ptr);
	}
	/* check if it isnt too large */
	while (((mpz_sizeinbase(*prime, 2) + 7) / 8) > prime_size);
	
	randomizer->destroy(randomizer);
	return SUCCESS;
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
	chunk_t em;
	chunk_t oid;
	
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
	em.ptr = malloc(em.len);
	
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
	
	free(hash.ptr);
	free(em.ptr);
	
	return SUCCESS;	
}

/**
 * Implementation of rsa_private_key.get_key.
 */
static status_t get_key(private_rsa_private_key_t *this, chunk_t *key)
{	
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
	key->ptr = malloc(key->len);
	memcpy(key->ptr + this->k * 0, n.ptr , n.len);
	memcpy(key->ptr + this->k * 1, e.ptr, e.len);
	memcpy(key->ptr + this->k * 2, p.ptr, p.len);
	memcpy(key->ptr + this->k * 3, q.ptr, q.len);
	memcpy(key->ptr + this->k * 4, d.ptr, d.len);
	memcpy(key->ptr + this->k * 5, exp1.ptr, exp1.len);
	memcpy(key->ptr + this->k * 6, exp2.ptr, exp2.len);
	memcpy(key->ptr + this->k * 7, coeff.ptr, coeff.len);
	
	free(n.ptr);
	free(e.ptr);
	free(p.ptr);
	free(q.ptr);
	free(d.ptr);
	free(exp1.ptr);
	free(exp2.ptr);
	free(coeff.ptr);
	
	return SUCCESS;
}

/**
 * Implementation of rsa_private_key.save_key.
 */
static status_t save_key(private_rsa_private_key_t *this, char *file)
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of rsa_private_key.get_public_key.
 */
rsa_public_key_t *get_public_key(private_rsa_private_key_t *this)
{
	return NULL;
}

/**
 * Implementation of rsa_private_key.belongs_to.
 */
static bool belongs_to(private_rsa_private_key_t *this, rsa_public_key_t *public)
{
	return chunk_equals(this->keyid, public->get_keyid(public));
}

/**
 * Check the loaded key if it is valid and usable
 * TODO: Log errors
 */
static status_t check(private_rsa_private_key_t *this)
{
	mpz_t t, u, q1;
	status_t status = SUCCESS;
	
	/* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
	* We actually require more (for security).
	*/
	if (this->k < 512/8)
	{
		return FAILED;
	}
	
	/* we picked a max modulus size to simplify buffer allocation */
	if (this->k > 8192/8)
	{
		return FAILED;
	}
	
	mpz_init(t);
	mpz_init(u);
	mpz_init(q1);
	
	/* check that n == p * q */
	mpz_mul(u, this->p, this->q);
	if (mpz_cmp(u, this->n) != 0)
	{
		status = FAILED;
	}
	
	/* check that e divides neither p-1 nor q-1 */
	mpz_sub_ui(t, this->p, 1);
	mpz_mod(t, t, this->e);
	if (mpz_cmp_ui(t, 0) == 0)
	{
		status = FAILED;
	}
	
	mpz_sub_ui(t, this->q, 1);
	mpz_mod(t, t, this->e);
	if (mpz_cmp_ui(t, 0) == 0)
	{
		status = FAILED;
	}
	
	/* check that d is e^-1 (mod lcm(p-1, q-1)) */
	/* see PKCS#1v2, aka RFC 2437, for the "lcm" */
	mpz_sub_ui(q1, this->q, 1);
	mpz_sub_ui(u, this->p, 1);
	mpz_gcd(t, u, q1);		/* t := gcd(p-1, q-1) */
	mpz_mul(u, u, q1);		/* u := (p-1) * (q-1) */
	mpz_divexact(u, u, t);	/* u := lcm(p-1, q-1) */
	
	mpz_mul(t, this->d, this->e);
	mpz_mod(t, t, u);
	if (mpz_cmp_ui(t, 1) != 0)
	{
		status = FAILED;
	}
	
	/* check that exp1 is d mod (p-1) */
	mpz_sub_ui(u, this->p, 1);
	mpz_mod(t, this->d, u);
	if (mpz_cmp(t, this->exp1) != 0)
	{
		status = FAILED;
	}
	
	/* check that exp2 is d mod (q-1) */
	mpz_sub_ui(u, this->q, 1);
	mpz_mod(t, this->d, u);
	if (mpz_cmp(t, this->exp2) != 0)
	{
		status = FAILED;
	}
	
	/* check that coeff is (q^-1) mod p */
	mpz_mul(t, this->coeff, this->q);
	mpz_mod(t, t, this->p);
	if (mpz_cmp_ui(t, 1) != 0)
	{
		status = FAILED;
	}
	
	mpz_clear(t);
	mpz_clear(u);
	mpz_clear(q1);
	return status;
}

/**
 * Implementation of rsa_private_key.clone.
 */
static rsa_private_key_t* _clone(private_rsa_private_key_t *this)
{
	private_rsa_private_key_t *clone = rsa_private_key_create_empty();
	
	mpz_init_set(clone->n, this->n);
	mpz_init_set(clone->e, this->e);
	mpz_init_set(clone->p, this->p);
	mpz_init_set(clone->q, this->q);
	mpz_init_set(clone->d, this->d);
	mpz_init_set(clone->exp1, this->exp1);
	mpz_init_set(clone->exp2, this->exp2);
	mpz_init_set(clone->coeff, this->coeff);
	clone->keyid = chunk_clone(this->keyid);
	clone->k = this->k;
	
	return &clone->public;
}

/**
 * Implementation of rsa_private_key.destroy.
 */
static void destroy(private_rsa_private_key_t *this)
{
	mpz_clear(this->n);
	mpz_clear(this->e);
	mpz_clear(this->p);
	mpz_clear(this->q);
	mpz_clear(this->d);
	mpz_clear(this->exp1);
	mpz_clear(this->exp2);
	mpz_clear(this->coeff);
	free(this->keyid.ptr);
	free(this);
}

/**
 * Internal generic constructor
 */
static private_rsa_private_key_t *rsa_private_key_create_empty(void)
{
	private_rsa_private_key_t *this = malloc_thing(private_rsa_private_key_t);
	
	/* public functions */
	this->public.build_emsa_pkcs1_signature = (status_t (*) (rsa_private_key_t*,hash_algorithm_t,chunk_t,chunk_t*))build_emsa_pkcs1_signature;
	this->public.get_key = (status_t (*) (rsa_private_key_t*,chunk_t*))get_key;
	this->public.save_key = (status_t (*) (rsa_private_key_t*,char*))save_key;
	this->public.get_public_key = (rsa_public_key_t *(*) (rsa_private_key_t*))get_public_key;
	this->public.belongs_to = (bool (*) (rsa_private_key_t*,rsa_public_key_t*))belongs_to;
	this->public.clone = (rsa_private_key_t*(*)(rsa_private_key_t*))_clone;
	this->public.destroy = (void (*) (rsa_private_key_t*))destroy;
	
	/* private functions */
	this->rsadp = rsadp;
	this->rsasp1 = rsadp; /* same algorithm */
	this->compute_prime = compute_prime;
	
	return this;
}

/*
 * See header
 */
rsa_private_key_t *rsa_private_key_create(size_t key_size)
{
	mpz_t p, q, n, e, d, exp1, exp2, coeff;
	mpz_t m, q1, t;
	private_rsa_private_key_t *this;
	
	this = rsa_private_key_create_empty();
	key_size = key_size / 8;
	
	/* Get values of primes p and q  */
	if (this->compute_prime(this, key_size/2, &p) != SUCCESS)
	{
		free(this);
		return NULL;
	}	
	if (this->compute_prime(this, key_size/2, &q) != SUCCESS)
	{
		mpz_clear(p);
		free(this);
		return NULL;
	}
	
	mpz_init(t);	
	mpz_init(n);
	mpz_init(d);
	mpz_init(exp1);
	mpz_init(exp2);
	mpz_init(coeff);
	
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
	this->k = key_size;
	
	return &this->public;
}

/*
 * see header
 */
rsa_private_key_t *rsa_private_key_create_from_chunk(chunk_t blob)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	private_rsa_private_key_t *this;
	
	this = rsa_private_key_create_empty();
	
	mpz_init(this->n);
	mpz_init(this->e);
	mpz_init(this->p);
	mpz_init(this->q);
	mpz_init(this->d);
	mpz_init(this->exp1);
	mpz_init(this->exp2);
	mpz_init(this->coeff);
	
	asn1_init(&ctx, blob, 0, FALSE);
	
	while (objectID < PRIV_KEY_ROOF) 
	{
		if (!extract_object(privkey_objects, &objectID, &object, &level, &ctx))
		{
			destroy(this);
			return FALSE;
		}
		switch (objectID)
		{
			case PRIV_KEY_VERSION:
				if (object.len > 0 && *object.ptr != 0)
				{
					destroy(this);
					return NULL;
				}
				break;
			case PRIV_KEY_MODULUS:
				mpz_import(this->n, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_PUB_EXP:
				mpz_import(this->e, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_PRIV_EXP:
				mpz_import(this->d, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_PRIME1:
				mpz_import(this->p, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_PRIME2:
				mpz_import(this->q, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_EXP1:
				mpz_import(this->exp1, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_EXP2:
				mpz_import(this->exp2, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PRIV_KEY_COEFF:
				mpz_import(this->coeff, object.len, 1, 1, 1, 0, object.ptr);
				break;
		}
		objectID++;
	}
	
	this->k = (mpz_sizeinbase(this->n, 2) + 7) / 8;

	/* form the keyid as a SHA-1 hash of a publicKeyInfo object */
	{
		chunk_t publicKeyInfo = rsa_public_key_info_to_asn1(this->n, this->e);
		hasher_t *hasher = hasher_create(HASH_SHA1);

		hasher->allocate_hash(hasher, publicKeyInfo, &this->keyid);
		hasher->destroy(hasher);
		free(publicKeyInfo.ptr);
	}
	
	if (check(this) != SUCCESS)
	{
		destroy(this);
		return NULL;
	}
	else
	{
		return &this->public;
	}
}

/*
 * see header
 */
rsa_private_key_t *rsa_private_key_create_from_file(char *filename, chunk_t *passphrase)
{
	bool pgp = FALSE;
	chunk_t chunk = CHUNK_INITIALIZER;
	rsa_private_key_t *key = NULL;

	if (!pem_asn1_load_file(filename, passphrase, "private key", &chunk, &pgp))
		return NULL;

	key = rsa_private_key_create_from_chunk(chunk);
	free(chunk.ptr);
	return key;
}
