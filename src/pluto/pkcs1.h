/* Support of PKCS#1 private key data structures
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2005 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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
 * RCSID $Id: pkcs1.h,v 1.14 2005/12/06 22:52:12 as Exp $
 */

#ifndef _PKCS1_H
#define _PKCS1_H

#include <gmp.h>    /* GNU Multi Precision library */

#include "defs.h"

typedef struct RSA_public_key RSA_public_key_t;

struct RSA_public_key
{
    char keyid[KEYID_BUF];	/* see ipsec_keyblobtoid(3) */

    /* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
    unsigned k;

    /* public: */
    MP_INT
	n,	/* modulus: p * q */
	e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

typedef struct RSA_private_key RSA_private_key_t;

struct RSA_private_key {
    struct RSA_public_key pub;	/* must be at start for RSA_show_public_key */

    MP_INT
	d,	/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
	p,	/* first secret prime */
	q,	/* second secret prime */
	dP,	/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
	dQ,	/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
	qInv;	/* (q^-1) mod p */
};

struct fld {
    const char *name;
    size_t offset;
};

extern const struct fld RSA_private_field[];
#define RSA_PRIVATE_FIELD_ELEMENTS	8

extern void init_RSA_public_key(RSA_public_key_t *rsa, chunk_t e, chunk_t n);
extern bool pkcs1_parse_private_key(chunk_t blob, RSA_private_key_t *key);
extern chunk_t pkcs1_build_private_key(const RSA_private_key_t *key);
extern chunk_t pkcs1_build_public_key(const RSA_public_key_t *rsa);
extern chunk_t pkcs1_build_publicKeyInfo(const RSA_public_key_t *rsa);
extern chunk_t pkcs1_build_signature(chunk_t tbs, int hash_alg
    , const RSA_private_key_t *key, bool bit_string);
extern bool compute_digest(chunk_t tbs, int alg, chunk_t *digest);
extern void sign_hash(const RSA_private_key_t *k, const u_char *hash_val
    , size_t hash_len, u_char *sig_val, size_t sig_len);
extern chunk_t RSA_encrypt(const RSA_public_key_t *key, chunk_t in);
extern bool RSA_decrypt(const RSA_private_key_t *key, chunk_t in
    , chunk_t *out);
extern bool same_RSA_public_key(const RSA_public_key_t *a
    , const RSA_public_key_t *b);
extern void form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize);
extern err_t RSA_private_key_sanity(RSA_private_key_t *k);
#ifdef DEBUG
extern void RSA_show_public_key(RSA_public_key_t *k);
extern void RSA_show_private_key(RSA_private_key_t *k);
#endif
extern void free_RSA_public_content(RSA_public_key_t *rsa);
extern void free_RSA_private_content(RSA_private_key_t *rsak);

#endif /* _PKCS1_H */
