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
 * RCSID $Id: pkcs1.c,v 1.17 2006/01/04 21:00:43 as Exp $
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <freeswan.h>
#include <libsha2/sha2.h>

#include "constants.h"
#include "defs.h"
#include "mp_defs.h"
#include "asn1.h"
#include "oid.h"
#include "log.h"
#include "pkcs1.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "rnd.h"

const struct fld RSA_private_field[] =
{
    { "Modulus",         offsetof(RSA_private_key_t, pub.n) },
    { "PublicExponent",  offsetof(RSA_private_key_t, pub.e) },

    { "PrivateExponent", offsetof(RSA_private_key_t, d) },
    { "Prime1",          offsetof(RSA_private_key_t, p) },
    { "Prime2",          offsetof(RSA_private_key_t, q) },
    { "Exponent1",       offsetof(RSA_private_key_t, dP) },
    { "Exponent2",       offsetof(RSA_private_key_t, dQ) },
    { "Coefficient",     offsetof(RSA_private_key_t, qInv) },
};

/* ASN.1 definition of a PKCS#1 RSA private key */

static const asn1Object_t privkeyObjects[] = {
  { 0, "RSAPrivateKey",			ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
  { 1,   "version",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
  { 1,   "modulus",			ASN1_INTEGER,      ASN1_BODY }, /*  2 */
  { 1,   "publicExponent",		ASN1_INTEGER,      ASN1_BODY }, /*  3 */
  { 1,   "privateExponent",		ASN1_INTEGER,      ASN1_BODY }, /*  4 */
  { 1,   "prime1",			ASN1_INTEGER,      ASN1_BODY }, /*  5 */
  { 1,   "prime2",			ASN1_INTEGER,      ASN1_BODY }, /*  6 */
  { 1,   "exponent1",			ASN1_INTEGER,      ASN1_BODY }, /*  7 */
  { 1,   "exponent2",			ASN1_INTEGER,      ASN1_BODY }, /*  8 */
  { 1,   "coefficient",			ASN1_INTEGER,      ASN1_BODY }, /*  9 */
  { 1,   "otherPrimeInfos",		ASN1_SEQUENCE,     ASN1_OPT |
							   ASN1_LOOP }, /* 10 */
  { 2,     "otherPrimeInfo",		ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
  { 3,       "prime",			ASN1_INTEGER,      ASN1_BODY }, /* 12 */
  { 3,       "exponent",		ASN1_INTEGER,      ASN1_BODY }, /* 13 */
  { 3,       "coefficient",		ASN1_INTEGER,      ASN1_BODY }, /* 14 */
  { 1,   "end opt or loop",		ASN1_EOC,          ASN1_END  }  /* 15 */
};

#define PKCS1_PRIV_KEY_VERSION		 1
#define PKCS1_PRIV_KEY_MODULUS		 2
#define PKCS1_PRIV_KEY_PUB_EXP		 3
#define PKCS1_PRIV_KEY_COEFF		 9
#define PKCS1_PRIV_KEY_ROOF		16


/*
 * forms the FreeS/WAN keyid from the public exponent e and modulus n
 */
void
form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize)
{
    /* eliminate leading zero bytes in modulus from ASN.1 coding */
    while (n.len > 1 && *n.ptr == 0x00)
    {
	n.ptr++;  n.len--;
    }

    /* form the FreeS/WAN keyid */
    keyid[0] = '\0';	/* in case of splitkeytoid failure */
    splitkeytoid(e.ptr, e.len, n.ptr, n.len, keyid, KEYID_BUF);

    /* return the RSA modulus size in octets */
    *keysize = n.len;
}

/*
 * initialize an RSA_public_key_t object
 */
void
init_RSA_public_key(RSA_public_key_t *rsa, chunk_t e, chunk_t n)
{
    n_to_mpz(&rsa->e, e.ptr, e.len);
    n_to_mpz(&rsa->n, n.ptr, n.len);

    form_keyid(e, n, rsa->keyid, &rsa->k);
}

#ifdef DEBUG
static void
RSA_show_key_fields(RSA_private_key_t *k, int fieldcnt)
{
    const struct fld *p;

    DBG_log(" keyid: *%s", k->pub.keyid);

    for (p = RSA_private_field; p < &RSA_private_field[fieldcnt]; p++)
    {
	MP_INT *n = (MP_INT *) ((char *)k + p->offset);
	size_t sz = mpz_sizeinbase(n, 16);
	char buf[RSA_MAX_OCTETS * 2 + 2];	/* ought to be big enough */

	passert(sz <= sizeof(buf));
	mpz_get_str(buf, 16, n);

	DBG_log(" %s: 0x%s", p->name, buf);
    }
}

/* debugging info that compromises security! */
void
RSA_show_private_key(RSA_private_key_t *k)
{
    RSA_show_key_fields(k, elemsof(RSA_private_field));
}

void
RSA_show_public_key(RSA_public_key_t *k)
{
    /* Kludge: pretend that it is a private key, but only display the
     * first two fields (which are the public key).
     */
    passert(offsetof(RSA_private_key_t, pub) == 0);
    RSA_show_key_fields((RSA_private_key_t *)k, 2);
}
#endif

err_t
RSA_private_key_sanity(RSA_private_key_t *k)
{
    /* note that the *last* error found is reported */
    err_t ugh = NULL;
    mpz_t t, u, q1;

#ifdef DEBUG	/* debugging info that compromises security */
    DBG(DBG_PRIVATE, RSA_show_private_key(k));
#endif

    /* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
     * We actually require more (for security).
     */
    if (k->pub.k < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    /* we picked a max modulus size to simplify buffer allocation */
    if (k->pub.k > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    mpz_init(t);
    mpz_init(u);
    mpz_init(q1);

    /* check that n == p * q */
    mpz_mul(u, &k->p, &k->q);
    if (mpz_cmp(u, &k->pub.n) != 0)
	ugh = "n != p * q";

    /* check that e divides neither p-1 nor q-1 */
    mpz_sub_ui(t, &k->p, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides p-1";

    mpz_sub_ui(t, &k->q, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides q-1";

    /* check that d is e^-1 (mod lcm(p-1, q-1)) */
    /* see PKCS#1v2, aka RFC 2437, for the "lcm" */
    mpz_sub_ui(q1, &k->q, 1);
    mpz_sub_ui(u, &k->p, 1);
    mpz_gcd(t, u, q1);		/* t := gcd(p-1, q-1) */
    mpz_mul(u, u, q1);		/* u := (p-1) * (q-1) */
    mpz_divexact(u, u, t);	/* u := lcm(p-1, q-1) */

    mpz_mul(t, &k->d, &k->pub.e);
    mpz_mod(t, t, u);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "(d * e) mod (lcm(p-1, q-1)) != 1";

    /* check that dP is d mod (p-1) */
    mpz_sub_ui(u, &k->p, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dP) != 0)
	ugh = "dP is not congruent to d mod (p-1)";

    /* check that dQ is d mod (q-1) */
    mpz_sub_ui(u, &k->q, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dQ) != 0)
	ugh = "dQ is not congruent to d mod (q-1)";

    /* check that qInv is (q^-1) mod p */
    mpz_mul(t, &k->qInv, &k->q);
    mpz_mod(t, t, &k->p);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "qInv is not conguent ot (q^-1) mod p";

    mpz_clear(t);
    mpz_clear(u);
    mpz_clear(q1);
    return ugh;
}

/*
 * Check the equality of two RSA public keys
 */
bool
same_RSA_public_key(const RSA_public_key_t *a, const RSA_public_key_t *b)
{
    return a == b
    || (a->k == b->k && mpz_cmp(&a->n, &b->n) == 0 && mpz_cmp(&a->e, &b->e) == 0);
}

/*
 *  Parses a PKCS#1 private key
 */
bool
pkcs1_parse_private_key(chunk_t blob, RSA_private_key_t *key)
{
    err_t ugh = NULL;
    asn1_ctx_t ctx;
    chunk_t object, modulus, exp;
    u_int level;
    int objectID = 0;

    asn1_init(&ctx, blob, 0, FALSE, DBG_PRIVATE);

    while (objectID < PKCS1_PRIV_KEY_ROOF) {

	if (!extract_object(privkeyObjects, &objectID, &object, &level, &ctx))
	     return FALSE;

	if (objectID == PKCS1_PRIV_KEY_VERSION)
	{
	    if (object.len > 0 && *object.ptr != 0)
	    {
		plog("  wrong PKCS#1 private key version");
		return FALSE;
	    }
	}
	else if (objectID >= PKCS1_PRIV_KEY_MODULUS &&
		 objectID <= PKCS1_PRIV_KEY_COEFF)
	{
	    MP_INT *u = (MP_INT *) ((char *)key
		+ RSA_private_field[objectID - PKCS1_PRIV_KEY_MODULUS].offset);

	    n_to_mpz(u, object.ptr, object.len);

	    if (objectID == PKCS1_PRIV_KEY_MODULUS)
		modulus = object;
	    else if (objectID == PKCS1_PRIV_KEY_PUB_EXP)
		exp = object;
	}
	objectID++;
    }
    form_keyid(exp, modulus, key->pub.keyid, &key->pub.k);
    ugh = RSA_private_key_sanity(key);
    return (ugh == NULL);
}

/*
 *  compute a digest over a binary blob
 */
bool
compute_digest(chunk_t tbs, int alg, chunk_t *digest)
{
    switch (alg)
    {
    case OID_MD2:
    case OID_MD2_WITH_RSA:
	{
	    MD2_CTX context;

	    MD2Init(&context);
	    MD2Update(&context, tbs.ptr, tbs.len);
	    MD2Final(digest->ptr, &context);
	    digest->len = MD2_DIGEST_SIZE;
	    return TRUE;
	}
     case OID_MD5:
     case OID_MD5_WITH_RSA:
	{
	    MD5_CTX context;

	    MD5Init(&context);
	    MD5Update(&context, tbs.ptr, tbs.len);
	    MD5Final(digest->ptr, &context);
	    digest->len = MD5_DIGEST_SIZE;
	    return TRUE;
	}
     case OID_SHA1:
     case OID_SHA1_WITH_RSA:
     case OID_SHA1_WITH_RSA_OIW:
	{
	    SHA1_CTX context;

	    SHA1Init(&context);
	    SHA1Update(&context, tbs.ptr, tbs.len);
	    SHA1Final(digest->ptr, &context);
	    digest->len = SHA1_DIGEST_SIZE;
	    return TRUE;
	}
     case OID_SHA256:
     case OID_SHA256_WITH_RSA:
	{
	    sha256_context context;

	    sha256_init(&context);
	    sha256_write(&context, tbs.ptr, tbs.len);
	    sha256_final(&context);
	    memcpy(digest->ptr, context.sha_out, SHA2_256_DIGEST_SIZE);
	    digest->len = SHA2_256_DIGEST_SIZE;
	    return TRUE;
	}
     case OID_SHA384:
     case OID_SHA384_WITH_RSA:
	{
	    sha512_context context;

	    sha384_init(&context);
	    sha512_write(&context, tbs.ptr, tbs.len);
	    sha512_final(&context);
	    memcpy(digest->ptr, context.sha_out, SHA2_384_DIGEST_SIZE);
	    digest->len = SHA2_384_DIGEST_SIZE;
	    return TRUE;
	}
     case OID_SHA512:
     case OID_SHA512_WITH_RSA:
	{
	    sha512_context context;

	    sha512_init(&context);
	    sha512_write(&context, tbs.ptr, tbs.len);
	    sha512_final(&context);
	    memcpy(digest->ptr, context.sha_out, SHA2_512_DIGEST_SIZE);
	    digest->len = SHA2_512_DIGEST_SIZE;
	    return TRUE;
	}
     default:
	digest->len = 0;
	return FALSE;
    }
}

/*
 * compute an RSA signature with PKCS#1 padding
 */
void
sign_hash(const RSA_private_key_t *k, const u_char *hash_val, size_t hash_len
    , u_char *sig_val, size_t sig_len)
{
    chunk_t ch;
    mpz_t t1, t2;
    size_t padlen;
    u_char *p = sig_val;

    DBG(DBG_CONTROL | DBG_CRYPT,
	DBG_log("signing hash with RSA Key *%s", k->pub.keyid)
    )
    /* PKCS#1 v1.5 8.1 encryption-block formatting */
    *p++ = 0x00;
    *p++ = 0x01;	/* BT (block type) 01 */
    padlen = sig_len - 3 - hash_len;
    memset(p, 0xFF, padlen);
    p += padlen;
    *p++ = 0x00;
    memcpy(p, hash_val, hash_len);
    passert(p + hash_len - sig_val == (ptrdiff_t)sig_len);

    /* PKCS#1 v1.5 8.2 octet-string-to-integer conversion */
    n_to_mpz(t1, sig_val, sig_len);	/* (could skip leading 0x00) */

    /* PKCS#1 v1.5 8.3 RSA computation y = x^c mod n
     * Better described in PKCS#1 v2.0 5.1 RSADP.
     * There are two methods, depending on the form of the private key.
     * We use the one based on the Chinese Remainder Theorem.
     */
    mpz_init(t2);

    mpz_powm(t2, t1, &k->dP, &k->p);	/* m1 = c^dP mod p */

    mpz_powm(t1, t1, &k->dQ, &k->q);	/* m2 = c^dQ mod Q */

    mpz_sub(t2, t2, t1);	/* h = qInv (m1 - m2) mod p */
    mpz_mod(t2, t2, &k->p);
    mpz_mul(t2, t2, &k->qInv);
    mpz_mod(t2, t2, &k->p);

    mpz_mul(t2, t2, &k->q);	/* m = m2 + h q */
    mpz_add(t1, t1, t2);

    /* PKCS#1 v1.5 8.4 integer-to-octet-string conversion */
    ch = mpz_to_n(t1, sig_len);
    memcpy(sig_val, ch.ptr, sig_len);
    pfree(ch.ptr);

    mpz_clear(t1);
    mpz_clear(t2);
}

/*
 * encrypt data with an RSA public key after padding
 */
chunk_t
RSA_encrypt(const RSA_public_key_t *key, chunk_t in)
{
    u_char padded[RSA_MAX_OCTETS];
    u_char *pos = padded;
    int padding = key->k - in.len - 3;
    int i;

    if (padding < 8 || key->k > RSA_MAX_OCTETS)
	return empty_chunk;

    /* add padding according to PKCS#1 7.2.1 1.+2. */
    *pos++ = 0x00;
    *pos++ = 0x02;

    /* pad with pseudo random bytes unequal to zero */
    get_rnd_bytes(pos, padding);
    for (i = 0; i < padding; i++)
    {
	while (!*pos)
 	  get_rnd_bytes(pos, 1);
	pos++;
    }

    /* append the padding terminator */
    *pos++ = 0x00;

    /* now add the data */
    memcpy(pos, in.ptr, in.len);
    DBG(DBG_RAW,
	DBG_dump_chunk("data for rsa encryption:\n", in);
	DBG_dump("padded data for rsa encryption:\n", padded, key->k)
    )

    /* convert chunk to integer (PKCS#1 7.2.1 3.a) */
    {
	chunk_t out;
	mpz_t m, c;

	mpz_init(c);
	n_to_mpz(m, padded, key->k);

	/* encrypt(PKCS#1 7.2.1 3.b) */
	mpz_powm(c, m, &key->e, &key->n);

	/* convert integer back to a chunk (PKCS#1 7.2.1 3.c) */
	out = mpz_to_n(c, key->k);
	mpz_clear(c);
	mpz_clear(m);

	DBG(DBG_RAW,
	    DBG_dump_chunk("rsa encrypted data:\n", out)
	)
	return out;
    }
}

/*
 * decrypt data with an RSA private key and remove padding
 */
bool
RSA_decrypt(const RSA_private_key_t *key, chunk_t in, chunk_t *out)
{
    chunk_t padded;
    u_char *pos;
    mpz_t t1, t2;

    n_to_mpz(t1, in.ptr,in.len);

    /* PKCS#1 v1.5 8.3 RSA computation y = x^c mod n
     * Better described in PKCS#1 v2.0 5.1 RSADP.
     * There are two methods, depending on the form of the private key.
     * We use the one based on the Chinese Remainder Theorem.
     */
    mpz_init(t2);

    mpz_powm(t2, t1, &key->dP, &key->p);	/* m1 = c^dP mod p */
    mpz_powm(t1, t1, &key->dQ, &key->q);	/* m2 = c^dQ mod Q */

    mpz_sub(t2, t2, t1);	/* h = qInv (m1 - m2) mod p */
    mpz_mod(t2, t2, &key->p);
    mpz_mul(t2, t2, &key->qInv);
    mpz_mod(t2, t2, &key->p);

    mpz_mul(t2, t2, &key->q);	/* m = m2 + h q */
    mpz_add(t1, t1, t2);

    padded = mpz_to_n(t1, key->pub.k);
    mpz_clear(t1);
    mpz_clear(t2);

    DBG(DBG_PRIVATE,
	DBG_dump_chunk("rsa decrypted data with padding:\n", padded)
    )
    pos = padded.ptr;

    /* PKCS#1 v1.5 8.1 encryption-block formatting (EB = 00 || 02 || PS || 00 || D) */

    /* check for hex pattern 00 02 in decrypted message */
    if ((*pos++ != 0x00) || (*(pos++) != 0x02))
    {
	plog("incorrect padding - probably wrong RSA key");
	freeanychunk(padded);
	return FALSE;
    }
    padded.len -= 2;

    /* the plaintext data starts after first 0x00 byte */
    while (padded.len-- > 0 && *pos++ != 0x00)

    if (padded.len == 0)
    {
	plog("no plaintext data");
	freeanychunk(padded);
	return FALSE;
    }

    clonetochunk(*out, pos, padded.len, "decrypted data");
    freeanychunk(padded);
    return TRUE;
}

/*
 * build signatureValue
 */
chunk_t
pkcs1_build_signature(chunk_t tbs, int hash_alg, const RSA_private_key_t *key
, bool bit_string)
{

    size_t siglen = key->pub.k;

    u_char digest_buf[MAX_DIGEST_LEN];
    chunk_t digest = { digest_buf, MAX_DIGEST_LEN };
    chunk_t digestInfo, alg_id, signatureValue;
    u_char *pos;

    switch (hash_alg)
    {
    case OID_MD5:
    case OID_MD5_WITH_RSA:
	alg_id = ASN1_md5_id;
	break;
    case OID_SHA1:
    case OID_SHA1_WITH_RSA:
	alg_id = ASN1_sha1_id;
	break;
    default:
	return empty_chunk;
    }
    compute_digest(tbs, hash_alg, &digest);

    /* according to PKCS#1 v2.1 digest must be packaged into
     * an ASN.1 structure for encryption
     */
    digestInfo = asn1_wrap(ASN1_SEQUENCE, "cm"
		    , alg_id
		    , asn1_simple_object(ASN1_OCTET_STRING, digest));

    /* generate the RSA signature */
    if (bit_string)
    {
	pos = build_asn1_object(&signatureValue, ASN1_BIT_STRING, 1 + siglen);
	*pos++ = 0x00;
    }
    else
    {
	pos = build_asn1_object(&signatureValue, ASN1_OCTET_STRING, siglen);
    }
    sign_hash(key, digestInfo.ptr, digestInfo.len, pos, siglen);
    pfree(digestInfo.ptr);

    return signatureValue;
}

/*
 * build a DER-encoded PKCS#1 private key object
 */
chunk_t
pkcs1_build_private_key(const RSA_private_key_t *key)
{
    chunk_t pkcs1 = asn1_wrap(ASN1_SEQUENCE, "cmmmmmmmm"
			, ASN1_INTEGER_0
			, asn1_integer_from_mpz(&key->pub.n)
			, asn1_integer_from_mpz(&key->pub.e)
			, asn1_integer_from_mpz(&key->d)
			, asn1_integer_from_mpz(&key->p)
			, asn1_integer_from_mpz(&key->q)
			, asn1_integer_from_mpz(&key->dP)
			, asn1_integer_from_mpz(&key->dQ)
			, asn1_integer_from_mpz(&key->qInv));

    DBG(DBG_PRIVATE,
	DBG_dump_chunk("PKCS#1 encoded private key:", pkcs1)
    )
    return pkcs1;
}

/*
 * build a DER-encoded PKCS#1 public key object
 */
chunk_t
pkcs1_build_public_key(const RSA_public_key_t *rsa)
{
    return asn1_wrap(ASN1_SEQUENCE, "mm"
		, asn1_integer_from_mpz(&rsa->n)
		, asn1_integer_from_mpz(&rsa->e));
}

/*
 * build a DER-encoded publicKeyInfo object
 */
chunk_t
pkcs1_build_publicKeyInfo(const RSA_public_key_t *rsa)
{
    chunk_t publicKey;
    chunk_t rawKey = pkcs1_build_public_key(rsa);

    u_char *pos = build_asn1_object(&publicKey, ASN1_BIT_STRING
			, 1 + rawKey.len);
    *pos++ = 0x00;
    mv_chunk(&pos, rawKey);

    return asn1_wrap(ASN1_SEQUENCE, "cm"
		, ASN1_rsaEncryption_id
		, publicKey);	
}
void
free_RSA_public_content(RSA_public_key_t *rsa)
{
    mpz_clear(&rsa->n);
    mpz_clear(&rsa->e);
}

void
free_RSA_private_content(RSA_private_key_t *rsak)
{
    free_RSA_public_content(&rsak->pub);
    mpz_clear(&rsak->d);
    mpz_clear(&rsak->p);
    mpz_clear(&rsak->q);
    mpz_clear(&rsak->dP);
    mpz_clear(&rsak->dQ);
    mpz_clear(&rsak->qInv);
}

