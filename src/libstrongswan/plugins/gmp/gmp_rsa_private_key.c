/*
 * Copyright (C) 2005-2008 Martin Willi
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
 * $Id$
 */

#include <gmp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "gmp_rsa_private_key.h"
#include "gmp_rsa_public_key.h"

#include <debug.h>
#include <asn1/asn1.h>

/**
 *  Public exponent to use for key generation.
 */
#define PUBLIC_EXPONENT 0x10001

typedef struct private_gmp_rsa_private_key_t private_gmp_rsa_private_key_t;

/**
 * Private data of a gmp_rsa_private_key_t object.
 */
struct private_gmp_rsa_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	gmp_rsa_private_key_t public;
	
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
	 * Keyid formed as a SHA-1 hash of a publicKey object
	 */
	identification_t* keyid;

	/**
	 * Keyid formed as a SHA-1 hash of a publicKeyInfo object
	 */
	identification_t* keyid_info;
	
	/**
	 * reference count
	 */
	refcount_t ref;	
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

/**
 * shared functions, implemented in gmp_rsa_public_key.c
 */
bool gmp_rsa_public_key_build_id(mpz_t n, mpz_t e, identification_t **keyid,
								 identification_t **keyid_info);
gmp_rsa_public_key_t *gmp_rsa_public_key_create_from_n_e(mpz_t n, mpz_t e);

/**
 * Auxiliary function overwriting private key material with zero bytes
 */
static void mpz_clear_randomized(mpz_t z)
{
	size_t len = mpz_size(z) * GMP_LIMB_BITS / BITS_PER_BYTE;
	u_int8_t *random = alloca(len);
	
	memset(random, 0, len);
	/* overwrite mpz_t with zero bytes before clearing it */
	mpz_import(z, len, 1, 1, 1, 0, random);
	mpz_clear(z);
}

/**
 * Create a mpz prime of at least prime_size
 */
static status_t compute_prime(private_gmp_rsa_private_key_t *this,
							  size_t prime_size, mpz_t *prime)
{
	rng_t *rng;
	chunk_t random_bytes;
	
	rng = lib->crypto->create_rng(lib->crypto, RNG_REAL);
	if (!rng)
	{
		DBG1("no RNG of quality %N found", rng_quality_names, RNG_REAL);
		return FAILED;
	}
	
	mpz_init(*prime);
	do
	{
		rng->allocate_bytes(rng, prime_size, &random_bytes);
		/* make sure most significant bit is set */
		random_bytes.ptr[0] = random_bytes.ptr[0] | 0x80;
		
		mpz_import(*prime, random_bytes.len, 1, 1, 1, 0, random_bytes.ptr);
		mpz_nextprime (*prime, *prime);
		chunk_clear(&random_bytes);
	}
	/* check if it isn't too large */
	while (((mpz_sizeinbase(*prime, 2) + 7) / 8) > prime_size);
	
	rng->destroy(rng);
	return SUCCESS;
}

/**
 * PKCS#1 RSADP function
 */
static chunk_t rsadp(private_gmp_rsa_private_key_t *this, chunk_t data)
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
 * PKCS#1 RSASP1 function
 */
static chunk_t rsasp1(private_gmp_rsa_private_key_t *this, chunk_t data)
{
	return rsadp(this, data);
}

/**
 * Implementation of gmp_rsa_private_key_t.build_emsa_pkcs1_signature.
 */
static bool build_emsa_pkcs1_signature(private_gmp_rsa_private_key_t *this,
									   hash_algorithm_t hash_algorithm,
									   chunk_t data, chunk_t *signature)
{
	hasher_t *hasher;
	chunk_t em, digestInfo, hash;
	int hash_oid = hasher_algorithm_to_oid(hash_algorithm);
	
	if (hash_oid == OID_UNKNOWN)
	{
		return FALSE;
	}

	/* get hasher */
	hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm);
	if (hasher == NULL)
	{
		return FALSE;
	}
	
	/* build hash */
	hasher->allocate_hash(hasher, data, &hash);
	hasher->destroy(hasher);
	
	/* build DER-encoded digestInfo */
	digestInfo = asn1_wrap(ASN1_SEQUENCE, "cm",
					asn1_algorithmIdentifier(hash_oid),
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
	*signature = rsasp1(this, em);
	
	free(digestInfo.ptr);
	free(em.ptr);
	
	return TRUE;	
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static key_type_t get_type(private_gmp_rsa_private_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static bool sign(private_gmp_rsa_private_key_t *this, signature_scheme_t scheme, 
				 chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_DEFAULT:
			/* default is EMSA-PKCS1 using SHA1 */
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return build_emsa_pkcs1_signature(this, HASH_SHA1, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return build_emsa_pkcs1_signature(this, HASH_SHA256, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return build_emsa_pkcs1_signature(this, HASH_SHA384, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return build_emsa_pkcs1_signature(this, HASH_SHA512, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return build_emsa_pkcs1_signature(this, HASH_MD5, data, signature);
		default:
			DBG1("signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static bool decrypt(private_gmp_rsa_private_key_t *this,
					chunk_t crypto, chunk_t *plain)
{
	DBG1("RSA private key decryption not implemented");
	return FALSE;
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static size_t get_keysize(private_gmp_rsa_private_key_t *this)
{
	return this->k;
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static identification_t* get_id(private_gmp_rsa_private_key_t *this,
								id_type_t type)
{
	switch (type)
	{
		case ID_PUBKEY_INFO_SHA1:
			return this->keyid_info;
		case ID_PUBKEY_SHA1:
			return this->keyid;
		default:
			return NULL;
	}
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static gmp_rsa_public_key_t* get_public_key(private_gmp_rsa_private_key_t *this)
{
	return gmp_rsa_public_key_create_from_n_e(this->n, this->e);
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static bool belongs_to(private_gmp_rsa_private_key_t *this, public_key_t *public)
{
	identification_t *keyid;

	if (public->get_type(public) != KEY_RSA)
	{
		return FALSE;
	}
	keyid = public->get_id(public, ID_PUBKEY_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid))
	{
		return TRUE;
	}
	keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid_info))
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * convert a MP integer into a DER coded ASN.1 object
 */
chunk_t gmp_mpz_to_asn1(const mpz_t value)
{
	size_t bits = mpz_sizeinbase(value, 2);  /* size in bits */
	chunk_t n;

	n.len = 1 + bits / 8;  /* size in bytes */	
	n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, value);

	return asn1_wrap(ASN1_INTEGER, "m", n);
}

/**
 * Implementation of private_key_t.get_encoding.
 */
static chunk_t get_encoding(private_gmp_rsa_private_key_t *this)
{
	return asn1_wrap(ASN1_SEQUENCE, "cmmmmmmmm",
					 ASN1_INTEGER_0,
					 gmp_mpz_to_asn1(this->n),
					 gmp_mpz_to_asn1(this->e),
					 gmp_mpz_to_asn1(this->d),
					 gmp_mpz_to_asn1(this->p),
					 gmp_mpz_to_asn1(this->q),
					 gmp_mpz_to_asn1(this->exp1),
					 gmp_mpz_to_asn1(this->exp2),
					 gmp_mpz_to_asn1(this->coeff));
}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static private_gmp_rsa_private_key_t* get_ref(private_gmp_rsa_private_key_t *this)
{
	ref_get(&this->ref);
	return this;

}

/**
 * Implementation of gmp_rsa_private_key.destroy.
 */
static void destroy(private_gmp_rsa_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		mpz_clear_randomized(this->n);
		mpz_clear_randomized(this->e);
		mpz_clear_randomized(this->p);
		mpz_clear_randomized(this->q);
		mpz_clear_randomized(this->d);
		mpz_clear_randomized(this->exp1);
		mpz_clear_randomized(this->exp2);
		mpz_clear_randomized(this->coeff);
		DESTROY_IF(this->keyid);
		DESTROY_IF(this->keyid_info);
		free(this);
	}
}

/**
 * Check the loaded key if it is valid and usable
 */
static status_t check(private_gmp_rsa_private_key_t *this)
{
	mpz_t t, u, q1;
	status_t status = SUCCESS;
	
	/* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
	* We actually require more (for security).
	*/
	if (this->k < 512/8)
	{
		DBG1("key shorter than 512 bits");
		return FAILED;
	}
	
	/* we picked a max modulus size to simplify buffer allocation */
	if (this->k > 8192/8)
	{
		DBG1("key larger thant 8192 bits");
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
	if (status != SUCCESS)
	{
		DBG1("key integrity tests failed");
	}
	return status;
}

/**
 * Internal generic constructor
 */
static private_gmp_rsa_private_key_t *gmp_rsa_private_key_create_empty(void)
{
	private_gmp_rsa_private_key_t *this = malloc_thing(private_gmp_rsa_private_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(private_key_t *this))get_type;
	this->public.interface.sign = (bool (*)(private_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t *signature))sign;
	this->public.interface.decrypt = (bool (*)(private_key_t *this, chunk_t crypto, chunk_t *plain))decrypt;
	this->public.interface.get_keysize = (size_t (*) (private_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (private_key_t *this,id_type_t))get_id;
	this->public.interface.get_public_key = (public_key_t* (*)(private_key_t *this))get_public_key;
	this->public.interface.belongs_to = (bool (*) (private_key_t *this, public_key_t *public))belongs_to;
	this->public.interface.get_encoding = (chunk_t(*)(private_key_t*))get_encoding;
	this->public.interface.get_ref = (private_key_t* (*)(private_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(private_key_t *this))destroy;
	
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Generate an RSA key of specified key size
 */
static gmp_rsa_private_key_t *generate(size_t key_size)
{
	mpz_t p, q, n, e, d, exp1, exp2, coeff;
	mpz_t m, q1, t;
	private_gmp_rsa_private_key_t *this = gmp_rsa_private_key_create_empty();
	
	key_size = key_size / 8;
	
	/* Get values of primes p and q  */
	if (compute_prime(this, key_size/2, &p) != SUCCESS)
	{
		free(this);
		return NULL;
	}	
	if (compute_prime(this, key_size/2, &q) != SUCCESS)
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
	mpz_gcd(t, m, e);						/* t = gcd(m, e) */

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

/**
 * load private key from a ASN1 encoded blob
 */
static gmp_rsa_private_key_t *load(chunk_t blob)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	private_gmp_rsa_private_key_t *this = gmp_rsa_private_key_create_empty();
	
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
			chunk_clear(&blob);
			destroy(this);
			return NULL;
		}
		switch (objectID)
		{
			case PRIV_KEY_VERSION:
				if (object.len > 0 && *object.ptr != 0)
				{
					chunk_clear(&blob);
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
	chunk_clear(&blob);
	
	this->k = (mpz_sizeinbase(this->n, 2) + 7) / BITS_PER_BYTE;
	if (!gmp_rsa_public_key_build_id(this->n, this->e,
									 &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	
	if (check(this) != SUCCESS)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading/generation
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded/generated private key */
	gmp_rsa_private_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static gmp_rsa_private_key_t *build(private_builder_t *this)
{
	gmp_rsa_private_key_t *key = this->key;
	
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	if (this->key)
	{
		DBG1("ignoring surplus build part %N", builder_part_names, part);
		return;
	}
	
	switch (part)
	{
		case BUILD_BLOB_ASN1_DER:
		{
			va_start(args, part);
			this->key = load(va_arg(args, chunk_t));
			va_end(args);
			break;
		}		
		case BUILD_KEY_SIZE:
		{
			va_start(args, part);
			this->key = generate(va_arg(args, u_int));
			va_end(args);
			break;
		}
		default:
			DBG1("ignoring unsupported build part %N", builder_part_names, part);
			break;
	}
}

/**
 * Builder construction function
 */
builder_t *gmp_rsa_private_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_RSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->key = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

