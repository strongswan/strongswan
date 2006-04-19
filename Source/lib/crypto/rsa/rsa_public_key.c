/**
 * @file rsa_public_key.c
 * 
 * @brief Implementation of rsa_public_key_t.
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
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "rsa_public_key.h"

#include <daemon.h>
#include <crypto/hashers/hasher.h>
#include <asn1/asn1.h>

/* 
 * For simplicity,
 * we use these predefined values for
 * hash algorithm OIDs. These also contain
 * the length of the following hash.
 * These values are also used in rsa_private_key.c.
 * TODO: We may move them in asn1 sometime...
 */

u_int8_t md2_oid[] = {
	0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,
	0x48,0x86,0xf7,0x0d,0x02,0x02,0x05,0x00,
	0x04,0x10
};

u_int8_t md5_oid[] = {
	0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,
	0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,
	0x04,0x10
};

u_int8_t sha1_oid[] = {
	0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,
	0x03,0x02,0x1a,0x05,0x00,0x04,0x14
};

u_int8_t sha256_oid[] = {
	0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,
	0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,
	0x00,0x04,0x20
};

u_int8_t sha384_oid[] = {
	0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,
	0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,
	0x00,0x04,0x30
};

u_int8_t sha512_oid[] = {
	0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,
	0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,
	0x00,0x04,0x40
};

/* ASN.1 definition public key */
static const asn1Object_t pubkey_objects[] = {
	{ 0, "RSAPublicKey",		ASN1_SEQUENCE,     ASN1_OBJ  }, /*  0 */
	{ 1,   "modulus",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
	{ 1,   "publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  2 */
};

#define PUB_KEY_RSA_PUBLIC_KEY		0
#define PUB_KEY_MODULUS				1
#define PUB_KEY_EXPONENT			2
#define PUB_KEY_ROOF				3

typedef struct private_rsa_public_key_t private_rsa_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_rsa_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	rsa_public_key_t public;
	
	/**
	 * Public modulus.
	 */
	mpz_t n;
	
	/**
	 * Public exponent.
	 */
	mpz_t e;
	
	/**
	 * Keysize in bytes.
	 */
	size_t k;
	
	/**
	 * @brief Implements the RSAEP algorithm specified in PKCS#1.
	 * 
	 * @param this		calling object
	 * @param data		data to process
	 * @return			processed data
	 */
	chunk_t (*rsaep) (private_rsa_public_key_t *this, chunk_t data);
		
	/**
	 * @brief Implements the RSASVP1 algorithm specified in PKCS#1.
	 * 
	 * @param this		calling object
	 * @param data		data to process
	 * @return			processed data
	 */
	chunk_t (*rsavp1) (private_rsa_public_key_t *this, chunk_t data);
};


typedef struct rsa_public_key_info_t rsa_public_key_info_t;

/**
 * KeyInfo, as it appears in a public key file
 */
struct rsa_public_key_info_t {
	/**
	 * Algorithm for this key
	 */
	chunk_t algorithm_oid;
	
	/**
	 * Public key, parseable with rsa_public_key_rules
	 */
	chunk_t public_key;
};

private_rsa_public_key_t *rsa_public_key_create_empty();

/**
 * Implementation of private_rsa_public_key_t.rsaep and private_rsa_public_key_t.rsavp1
 */
static chunk_t rsaep(private_rsa_public_key_t *this, chunk_t data)
{
	mpz_t m, c;
	chunk_t encrypted;
	
	mpz_init(c);
	mpz_init(m);
	
	mpz_import(m, data.len, 1, 1, 1, 0, data.ptr);
	
	mpz_powm(c, m, this->e, this->n);

    encrypted.len = this->k;
    encrypted.ptr = mpz_export(NULL, NULL, 1, encrypted.len, 1, 0, c);
	
	mpz_clear(c);
	mpz_clear(m);	
	
	return encrypted;
}

/**
 * Implementation of rsa_public_key.verify_emsa_pkcs1_signature.
 */
static status_t verify_emsa_pkcs1_signature(private_rsa_public_key_t *this, chunk_t data, chunk_t signature)
{
	hasher_t *hasher = NULL;
	chunk_t hash;
	chunk_t em;
	u_int8_t *pos;
	
	if (signature.len > this->k)
	{
		return INVALID_ARG;	
	}
	
	/* unpack signature */
	em = this->rsavp1(this, signature);
	
	/* result should look like this:
	 * EM = 0x00 || 0x01 || PS || 0x00 || T. 
	 * PS = 0xFF padding, with length to fill em
	 * T = oid || hash
	 */	
	
	/* check magic bytes */
	if ((*(em.ptr) != 0x00) ||
		(*(em.ptr+1) != 0x01))
	{
		free(em.ptr);
		return FAILED;
	}
	
	/* find magic 0x00 */
	pos = em.ptr + 2;
	while (pos <= em.ptr + em.len)
	{
		if (*pos == 0x00)
		{
			/* found magic byte, stop */
			pos++;
			break;
		}
		else if (*pos != 0xFF)
		{
			/* bad padding, decryption failed ?!*/
			free(em.ptr);
			return FAILED;	
		}
		pos++;
	}

	if (pos + 20 > em.ptr + em.len)
	{
		/* not enought room for oid compare */
		free(em.ptr);
		return FAILED;	
	}
	
	if (memcmp(md2_oid, pos, sizeof(md2_oid)) == 0)
	{
		hasher = hasher_create(HASH_MD2);
		pos += sizeof(md2_oid);
	}
	else if (memcmp(md5_oid, pos, sizeof(md5_oid)) == 0)
	{
		hasher = hasher_create(HASH_MD5);
		pos += sizeof(md5_oid);
	}
	else if (memcmp(sha1_oid, pos, sizeof(sha1_oid)) == 0)
	{
		hasher = hasher_create(HASH_SHA1);
		pos += sizeof(sha1_oid);
	}
	else if (memcmp(sha256_oid, pos, sizeof(sha256_oid)) == 0)
	{
		hasher = hasher_create(HASH_SHA256);
		pos += sizeof(sha256_oid);
	}
	else if (memcmp(sha384_oid, pos, sizeof(sha384_oid)) == 0)
	{
		hasher = hasher_create(HASH_SHA384);
		pos += sizeof(sha384_oid);
	}
	else if (memcmp(sha512_oid, pos, sizeof(sha512_oid)) == 0)
	{
		hasher = hasher_create(HASH_SHA512);
		pos += sizeof(sha512_oid);
	}
	
	if (hasher == NULL)
	{
		/* not supported hash algorithm */
		free(em.ptr);
		return NOT_SUPPORTED;	
	}
	
	if (pos + hasher->get_block_size(hasher) != em.ptr + em.len)
	{
		/* bad length */
		free(em.ptr);
		hasher->destroy(hasher);
		return FAILED;	
	}
	
	/* build own hash for a compare */
	hasher->allocate_hash(hasher, data, &hash);
	hasher->destroy(hasher);
	
	if (memcmp(hash.ptr, pos, hash.len) != 0)
	{
		/* hash does not equal */
		free(hash.ptr);
		free(em.ptr);
		return FAILED;	
			
	}
	
	/* seems good */
	free(hash.ptr);
	free(em.ptr);
	return SUCCESS;	
}
	
/**
 * Implementation of rsa_public_key.get_key.
 */
static status_t get_key(private_rsa_public_key_t *this, chunk_t *key)
{	
	chunk_t n, e;

	n.len = this->k;
	n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, this->n);
	e.len = this->k;
	e.ptr = mpz_export(NULL, NULL, 1, e.len, 1, 0, this->e);
	
	key->len = this->k * 2;
	key->ptr = malloc(key->len);
	memcpy(key->ptr, n.ptr, n.len);
	memcpy(key->ptr + n.len, e.ptr, e.len);
	free(n.ptr);
	free(e.ptr);
	
	return SUCCESS;
}

/**
 * Implementation of rsa_public_key.save_key.
 */
static status_t save_key(private_rsa_public_key_t *this, char *file)
{
	return NOT_SUPPORTED;
}

/**
 * Implementation of rsa_public_key.get_modulus.
 */
static mpz_t *get_modulus(private_rsa_public_key_t *this)
{
	return &this->n;
}

/**
 * Implementation of rsa_public_key.clone.
 */
static rsa_public_key_t* _clone(private_rsa_public_key_t *this)
{
	private_rsa_public_key_t *clone = rsa_public_key_create_empty();
	
	mpz_init_set(clone->n, this->n);
	mpz_init_set(clone->e, this->e);
	clone->k = this->k;
	
	return &clone->public;
}

/**
 * Implementation of rsa_public_key.destroy.
 */
static void destroy(private_rsa_public_key_t *this)
{
	mpz_clear(this->n);
	mpz_clear(this->e);
	free(this);
}

/**
 * Generic private constructor
 */
private_rsa_public_key_t *rsa_public_key_create_empty()
{
	private_rsa_public_key_t *this = malloc_thing(private_rsa_public_key_t);
	
	/* public functions */
	this->public.verify_emsa_pkcs1_signature = (status_t (*) (rsa_public_key_t*,chunk_t,chunk_t))verify_emsa_pkcs1_signature;
	this->public.get_key = (status_t (*) (rsa_public_key_t*,chunk_t*))get_key;
	this->public.save_key = (status_t (*) (rsa_public_key_t*,char*))save_key;
	this->public.get_modulus = (mpz_t *(*) (rsa_public_key_t*))get_modulus;
	this->public.clone = (rsa_public_key_t* (*) (rsa_public_key_t*))_clone;
	this->public.destroy = (void (*) (rsa_public_key_t*))destroy;
	
	/* private functions */
	this->rsaep = rsaep;
	this->rsavp1 = rsaep; /* same algorithm */
	
	return this;
}
	
/*
 * See header
 */
rsa_public_key_t *rsa_public_key_create_from_chunk(chunk_t blob)
{
	asn1_ctx_t ctx;
	chunk_t object;
	u_int level;
	int objectID = 0;
	private_rsa_public_key_t *this;
	
	this = rsa_public_key_create_empty();
	mpz_init(this->n);
	mpz_init(this->e);
	
	asn1_init(&ctx, blob, 0, FALSE);
	
	while (objectID < PUB_KEY_ROOF) 
	{
		if (!extract_object(pubkey_objects, &objectID, &object, &level, &ctx))
		{
			destroy(this);
			return FALSE;
		}
		switch (objectID)
		{
			case PUB_KEY_MODULUS:
				mpz_import(this->n, object.len, 1, 1, 1, 0, object.ptr);
				break;
			case PUB_KEY_EXPONENT:
				mpz_import(this->e, object.len, 1, 1, 1, 0, object.ptr);
				break;
		}
		objectID++;
	}
	
	this->k = (mpz_sizeinbase(this->n, 2) + 7) / 8;
	return &this->public;
}

/*
 * See header
 */
rsa_public_key_t *rsa_public_key_create_from_file(char *filename)
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
	
	if (fread(buffer, stb.st_size, 1, file) != 1)
	{
		return NULL;
	}
	
	chunk.ptr = buffer;
	chunk.len = stb.st_size;
	
	return rsa_public_key_create_from_chunk(chunk);
}
