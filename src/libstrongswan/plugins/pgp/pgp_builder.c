/*
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2002-2009 Andreas Steffen
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

#include "pgp_builder.h"

#include <debug.h>
#include <credentials/keys/private_key.h>


ENUM_BEGIN(pgp_packet_tag_names, PGP_PKT_RESERVED, PGP_PKT_PUBLIC_SUBKEY,
	"Reserved",
	"Public-Key Encrypted Session Key Packet",
	"Signature Packet",
	"Symmetric-Key Encrypted Session Key Packet",
	"One-Pass Signature Packet",
	"Secret Key Packet",
	"Public Key Packet",
	"Secret Subkey Packet",
	"Compressed Data Packet",
	"Symmetrically Encrypted Data Packet",
	"Marker Packet",
	"Literal Data Packet",
	"Trust Packet",
	"User ID Packet",
	"Public Subkey Packet"
);
ENUM_NEXT(pgp_packet_tag_names, PGP_PKT_USER_ATTRIBUTE, PGP_PKT_MOD_DETECT_CODE, PGP_PKT_PUBLIC_SUBKEY,
	"User Attribute Packet",
	"Sym. Encrypted and Integrity Protected Data Packet",
	"Modification Detection Code Packet"
);
ENUM_END(pgp_packet_tag_names, PGP_PKT_MOD_DETECT_CODE);

ENUM_BEGIN(pgp_pubkey_alg_names, PGP_PUBKEY_ALG_RSA, PGP_PUBKEY_ALG_RSA_SIGN_ONLY,
	"RSA",
	"RSA_ENC_ONLY",
	"RSA_SIGN_ONLY"
);
ENUM_NEXT(pgp_pubkey_alg_names, PGP_PUBKEY_ALG_ELGAMAL_ENC_ONLY, PGP_PUBKEY_ALG_DIFFIE_HELLMAN, PGP_PUBKEY_ALG_RSA_SIGN_ONLY,
	"ELGAMAL_ENC_ONLY",
	"DSA",
	"ECC",
	"ECDSA",
	"ELGAMAL",
	"DIFFIE_HELLMAN"
);
ENUM_END(pgp_pubkey_alg_names, PGP_PUBKEY_ALG_DIFFIE_HELLMAN);

ENUM(pgp_sym_alg_names, PGP_SYM_ALG_PLAIN, PGP_SYM_ALG_TWOFISH,
	"PLAINTEXT",
	"IDEA",
	"3DES",
	"CAST5",
	"BLOWFISH",
	"SAFER",
	"DES",
	"AES_128",
	"AES_192",
	"AES_256",
	"TWOFISH"
);

/**
 * Read a PGP scalar of bytes length, advance blob
 */
static bool read_scalar(chunk_t *blob, size_t bytes, u_int32_t *scalar)
{
	u_int32_t res = 0;
	
	if (bytes > blob->len)
	{
		DBG1("PGP data too short to read %d byte scalar", bytes);
		return FALSE;
	}
	while (bytes-- > 0)
	{
		res = 256 * res + blob->ptr[0];
		*blob = chunk_skip(*blob, 1);
	}
	*scalar = res;
	return TRUE;
}

/**
 * Read a PGP MPI, advance blob
 */
static bool read_mpi(chunk_t *blob, chunk_t *mpi)
{
	u_int32_t bits, bytes;
	
	if (!read_scalar(blob, 2, &bits))
	{
		DBG1("PGP data too short to read MPI length");
		return FALSE;
	}
	bytes = (bits + 7) / 8;
	if (bytes > blob->len)
	{
		DBG1("PGP data too short to %d byte MPI", bytes);
		return FALSE;
	}
	*mpi = chunk_create(blob->ptr, bytes);
	*blob = chunk_skip(*blob, bytes);
	return TRUE;
}

/**
 * Load a generic public key from a PGP packet
 */
static public_key_t *parse_public_key(chunk_t blob)
{
	u_int32_t alg;
	public_key_t *key;
	
	if (!read_scalar(&blob, 1, &alg))
	{
		return NULL;
	}
	switch (alg)
	{
		case PGP_PUBKEY_ALG_RSA:
		case PGP_PUBKEY_ALG_RSA_SIGN_ONLY:
			key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
									 BUILD_BLOB_PGP, blob, BUILD_END);
			break;
		default:
			DBG1("PGP public key algorithm %N not supported",
				 pgp_pubkey_alg_names, alg);
			return NULL;
	}
	return key;
}

/**
 * Load a RSA public key from a PGP packet
 */
static public_key_t *parse_rsa_public_key(chunk_t blob)
{
	chunk_t mpi[2];
	int i;
	
	for (i = 0; i < 2; i++)
	{
		if (!read_mpi(&blob, &mpi[i]))
		{
			return NULL;
		}
	}
	return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
						BUILD_RSA_MODULUS, mpi[0], BUILD_RSA_PUB_EXP, mpi[1],
						BUILD_END);
}

/**
 * Load a RSA private key from a PGP packet
 */
static private_key_t *parse_rsa_private_key(chunk_t blob)
{
	chunk_t mpi[6];
	u_int32_t s2k;
	int i;
	
	for (i = 0; i < 2; i++)
	{
		if (!read_mpi(&blob, &mpi[i]))
		{
			return NULL;
		}
	}
	if (!read_scalar(&blob, 1, &s2k))
	{
		return NULL;
	}
	if (s2k == 255 || s2k == 254)
	{
		DBG1("string-to-key specifiers not supported");
		return NULL;
	}
	if (s2k != PGP_SYM_ALG_PLAIN)
	{
		DBG1("%N private key encryption not supported", pgp_sym_alg_names, s2k);
		return NULL;
	}
	
	for (i = 2; i < 6; i++)
	{
		if (!read_mpi(&blob, &mpi[i]))
		{
			return NULL;
		}
	}
	/* PGP has uses p < q, but we use p > q */
	return lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA, 
						BUILD_RSA_MODULUS, mpi[0], BUILD_RSA_PUB_EXP, mpi[1],
						BUILD_RSA_PRIV_EXP, mpi[2], BUILD_RSA_PRIME2, mpi[3],
						BUILD_RSA_PRIME1, mpi[4], BUILD_RSA_COEFF, mpi[5],
						BUILD_END);
}

typedef struct private_builder_t private_builder_t;

/**
 * Builder implementation for private/public key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** PGP packet data */
	chunk_t blob;
	/** type of key to build */
	key_type_t type;
};

/**
 * Implementation of builder_t.build for public keys
 */
static public_key_t *build_public(private_builder_t *this)
{
	public_key_t *key = NULL;
	
	switch (this->type)
	{
		case KEY_ANY:
			key = parse_public_key(this->blob);
			break;
		case KEY_RSA:
			key = parse_rsa_public_key(this->blob);
			break;
		default:
			break;
	}
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add for public keys
 */
static void add_public(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	switch (part)
	{
		case BUILD_BLOB_PEM:
		{
			va_start(args, part);
			this->blob = va_arg(args, chunk_t);
			va_end(args);
			break;
		}
		default:
			builder_cancel(&this->public);
			break;
	}
}

/**
 * Builder construction function for public keys
 */
builder_t *pgp_public_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_ANY && type != KEY_RSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->blob = chunk_empty;
	this->type = type;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add_public;
	this->public.build = (void*(*)(builder_t *this))build_public;
	
	return &this->public;
}

/**
 * Implementation of builder_t.build for private keys
 */
static private_key_t *build_private(private_builder_t *this)
{
	private_key_t *key;
	
	key = parse_rsa_private_key(this->blob);
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add for private keys
 */
static void add_private(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	switch (part)
	{
		case BUILD_BLOB_PGP:
		{
			va_start(args, part);
			this->blob = va_arg(args, chunk_t);
			va_end(args);
			break;
		}
		default:
			builder_cancel(&this->public);
			break;
	}
}

/**
 * Builder construction function for private keys
 */
builder_t *pgp_private_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_RSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->blob = chunk_empty;
	this->type = type;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add_private;
	this->public.build = (void*(*)(builder_t *this))build_private;
	
	return &this->public;
}

