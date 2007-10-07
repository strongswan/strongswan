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
 *
 * RCSID $Id$
 */

#include <gmp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "rsa_public_key.h"
#include "rsa_private_key.h"

#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/pem.h>
#include <utils/randomizer.h>

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
	{ 0, "RSAPrivateKey",		ASN1_SEQUENCE,	ASN1_NONE }, /*  0 */
	{ 1,   "version",			ASN1_INTEGER,	ASN1_BODY }, /*  1 */
	{ 1,   "modulus",			ASN1_INTEGER,	ASN1_BODY }, /*  2 */
	{ 1,   "publicExponent",	ASN1_INTEGER,	ASN1_BODY }, /*  3 */
	{ 1,   "privateExponent",	ASN1_INTEGER,	ASN1_BODY }, /*  4 */
	{ 1,   "prime1",			ASN1_INTEGER,	ASN1_BODY }, /*  5 */
	{ 1,   "prime2",			ASN1_INTEGER,	ASN1_BODY }, /*  6 */
	{ 1,   "exponent1",			ASN1_INTEGER,	ASN1_BODY }, /*  7 */
	{ 1,   "exponent2",			ASN1_INTEGER,	ASN1_BODY }, /*  8 */
	{ 1,   "coefficient",		ASN1_INTEGER,	ASN1_BODY }, /*  9 */
	{ 1,   "otherPrimeInfos",	ASN1_SEQUENCE,	ASN1_OPT |
												ASN1_LOOP }, /* 10 */
	{ 2,     "otherPrimeInfo",	ASN1_SEQUENCE,	ASN1_NONE }, /* 11 */
	{ 3,       "prime",			ASN1_INTEGER,	ASN1_BODY }, /* 12 */
	{ 3,       "exponent",		ASN1_INTEGER,	ASN1_BODY }, /* 13 */
	{ 3,       "coefficient",	ASN1_INTEGER,	ASN1_BODY }, /* 14 */
	{ 1,   "end opt or loop",	ASN1_EOC,		ASN1_END  }  /* 15 */
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
 * Auxiliary function overwriting private key material with
 * pseudo-random bytes before releasing it
 */
static void mpz_clear_randomized(mpz_t z)
{
	size_t len = mpz_size(z) * GMP_LIMB_BITS / BITS_PER_BYTE;
	u_int8_t *random_bytes = alloca(len);

	randomizer_t *randomizer = randomizer_create();
	
	randomizer->get_pseudo_random_bytes(randomizer, len, random_bytes);

	/* overwrite mpz_t with pseudo-random bytes before clearing it */
	mpz_import(z, len, 1, 1, 1, 0, random_bytes);
	mpz_clear(z);

	randomizer->destroy(randomizer);
}

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
		
		/* free the random_bytes after overwriting them with a pseudo-random sequence */
		chunk_free_randomized(&random_bytes);
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
	
	mpz_clear_randomized(t1);
	mpz_clear_randomized(t2);
	
	return decrypted;
}

/**
 * Implementation of rsa_private_key_t.eme_pkcs1_decrypt.
 */
static status_t eme_pkcs1_decrypt(private_rsa_private_key_t *this,
								  chunk_t in, chunk_t *out)
{
	status_t status = FAILED;
	chunk_t em, em_ori;

	/* decrypt the input data */
	em = em_ori = this->rsadp(this, in);

	/* PKCS#1 v1.5 EME encryption formatting
	 * EM = 00 || 02 || PS || 00 || M
	 * PS = pseudo-random nonzero octets
	 */

	/* check for magic bytes */
	if (*(em.ptr) != 0x00 || *(em.ptr+1) != 0x02)
	{
		DBG1("incorrect padding - probably wrong RSA key");
		goto end;
	}
	em.ptr += 2;
	em.len -= 2;

	/* the plaintext data starts after first 0x00 byte */
	while (em.len-- > 0 && *em.ptr++ != 0x00);

	if (em.len == 0)
	{
		DBG1("no plaintext data found");
		goto end;
	}

    *out = chunk_clone(em);
    status = SUCCESS;

end:
	free(em_ori.ptr);
	return status;
}

/**
 * Implementation of rsa_private_key_t.build_emsa_pkcs1_signature.
 */
static status_t build_emsa_pkcs1_signature(private_rsa_private_key_t *this,
										   hash_algorithm_t hash_algorithm,
										   chunk_t data, chunk_t *signature)
{
	hasher_t *hasher;
	chunk_t em, digestInfo, hash_id, hash;
	
	/* get oid string prepended to hash */
	switch (hash_algorithm)
	{	
		case HASH_MD2:
		{
			hash_id =ASN1_md2_id;
			break;
		}
		case HASH_MD5:
		{
			hash_id = ASN1_md5_id;
			break;
		}
		case HASH_SHA1:
		{
			hash_id = ASN1_sha1_id;
			break;
		}
		case HASH_SHA256:
		{
			hash_id = ASN1_sha256_id;
			break;
		}
		case HASH_SHA384:
		{
			hash_id = ASN1_sha384_id;
			break;
		}
		case HASH_SHA512:
		{
			hash_id = ASN1_sha512_id;
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
	
	/* build DER-encoded digestInfo */
	digestInfo = asn1_wrap(ASN1_SEQUENCE, "cm",
					hash_id,
					asn1_simple_object(ASN1_OCTET_STRING, hash)
				  );
	chunk_free(&hash);

	/* build chunk to rsa-decrypt:
	 * EM = 0x00 || 0x01 || PS || 0x00 || T. 
	 * PS = 0xFF padding, with length to fill em
	 * T = encoded_hash
	 */
	em.len = this->k;
	em.ptr = malloc(em.len);
	
	/* fill em with padding */
	memset(em.ptr, 0xFF, em.len);
	/* set magic bytes */
	*(em.ptr) = 0x00;
	*(em.ptr+1) = 0x01;
	*(em.ptr + em.len - digestInfo.len - 1) = 0x00;
	/* set DER-encoded hash */
	memcpy(em.ptr + em.len - digestInfo.len, digestInfo.ptr, digestInfo.len);

	/* build signature */
	*signature = this->rsasp1(this, em);
	
	free(digestInfo.ptr);
	free(em.ptr);
	
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
	
	mpz_clear_randomized(t);
	mpz_clear_randomized(u);
	mpz_clear_randomized(q1);
	return status;
}

/**
 * Implementation of rsa_private_key.destroy.
 */
static void destroy(private_rsa_private_key_t *this)
{
	mpz_clear_randomized(this->n);
	mpz_clear_randomized(this->e);
	mpz_clear_randomized(this->p);
	mpz_clear_randomized(this->q);
	mpz_clear_randomized(this->d);
	mpz_clear_randomized(this->exp1);
	mpz_clear_randomized(this->exp2);
	mpz_clear_randomized(this->coeff);
	chunk_free_randomized(&this->keyid);
	free(this);
}

/**
 * Internal generic constructor
 */
static private_rsa_private_key_t *rsa_private_key_create_empty(void)
{
	private_rsa_private_key_t *this = malloc_thing(private_rsa_private_key_t);
	
	/* public functions */
	this->public.eme_pkcs1_decrypt = (status_t (*) (rsa_private_key_t*,chunk_t,chunk_t*))eme_pkcs1_decrypt;
	this->public.build_emsa_pkcs1_signature = (status_t (*) (rsa_private_key_t*,hash_algorithm_t,chunk_t,chunk_t*))build_emsa_pkcs1_signature;
	this->public.save_key = (status_t (*) (rsa_private_key_t*,char*))save_key;
	this->public.get_public_key = (rsa_public_key_t *(*) (rsa_private_key_t*))get_public_key;
	this->public.belongs_to = (bool (*) (rsa_private_key_t*,rsa_public_key_t*))belongs_to;
	this->public.destroy = (void (*) (rsa_private_key_t*))destroy;
	
	/* private functions */
	this->rsadp = rsadp;
	this->rsasp1 = rsadp; /* same algorithm */
	this->compute_prime = compute_prime;
	
	this->keyid = chunk_empty;
	
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
		mpz_swap(p, q);
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

	mpz_clear_randomized(q1);
	mpz_clear_randomized(m);
	mpz_clear_randomized(t);

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
	
	asn1_init(&ctx, blob, 0, FALSE, TRUE);
	
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
	
	this->k = (mpz_sizeinbase(this->n, 2) + 7) / BITS_PER_BYTE;

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
	chunk_t chunk = chunk_empty;
	rsa_private_key_t *key = NULL;

	if (!pem_asn1_load_file(filename, passphrase, "private key", &chunk, &pgp))
		return NULL;

	key = rsa_private_key_create_from_chunk(chunk);
	chunk_free_randomized(&chunk);
	return key;
}
