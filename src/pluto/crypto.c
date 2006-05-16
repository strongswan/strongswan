/* crypto interfaces
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: crypto.c,v 1.5 2005/12/06 22:51:34 as Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <freeswan.h>
#define HEADER_DES_LOCL_H   /* stupid trick to force prototype decl in <des.h> */
#include <libdes/des.h>

#include <errno.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "log.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "alg_info.h"
#include "ike_alg.h"


/* moduli and generator. */

static MP_INT
    modp1024_modulus,
    modp1536_modulus,
    modp2048_modulus,
    modp3072_modulus,
    modp4096_modulus,
    modp6144_modulus,
    modp8192_modulus;

MP_INT groupgenerator;	/* MODP group generator (2) */

static void do_3des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc);

static struct encrypt_desc crypto_encryptor_3des =
{ 	
	algo_type: 	IKE_ALG_ENCRYPT,
	algo_id:   	OAKLEY_3DES_CBC, 
	algo_next: 	NULL,
	enc_ctxsize: 	sizeof(des_key_schedule) * 3,
	enc_blocksize: 	DES_CBC_BLOCK_SIZE, 
	keydeflen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	keyminlen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	keymaxlen: 	DES_CBC_BLOCK_SIZE * 3 * BITS_PER_BYTE,
	do_crypt: 	do_3des,
};

static struct hash_desc crypto_hasher_md5 =
{ 	
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_MD5,
	algo_next: NULL, 
	hash_ctx_size: sizeof(MD5_CTX),
	hash_digest_size: MD5_DIGEST_SIZE,
	hash_init: (void (*)(void *)) MD5Init,
	hash_update: (void (*)(void *, const u_int8_t *, size_t)) MD5Update,
	hash_final: (void (*)(u_char *, void *)) MD5Final,
};

static struct hash_desc crypto_hasher_sha1 =
{ 	
	algo_type: IKE_ALG_HASH,
	algo_id:   OAKLEY_SHA,
	algo_next: NULL, 
	hash_ctx_size: sizeof(SHA1_CTX),
	hash_digest_size: SHA1_DIGEST_SIZE,
	hash_init: (void (*)(void *)) SHA1Init,
	hash_update: (void (*)(void *, const u_int8_t *, size_t)) SHA1Update,
	hash_final: (void (*)(u_char *, void *)) SHA1Final,
};

void
init_crypto(void)
{
    if (mpz_init_set_str(&groupgenerator, MODP_GENERATOR, 10) != 0
    || mpz_init_set_str(&modp1024_modulus, MODP1024_MODULUS, 16) != 0
    || mpz_init_set_str(&modp1536_modulus, MODP1536_MODULUS, 16) != 0
    || mpz_init_set_str(&modp2048_modulus, MODP2048_MODULUS, 16) != 0
    || mpz_init_set_str(&modp3072_modulus, MODP3072_MODULUS, 16) != 0
    || mpz_init_set_str(&modp4096_modulus, MODP4096_MODULUS, 16) != 0
    || mpz_init_set_str(&modp6144_modulus, MODP6144_MODULUS, 16) != 0
    || mpz_init_set_str(&modp8192_modulus, MODP8192_MODULUS, 16) != 0)
	exit_log("mpz_init_set_str() failed in init_crypto()");

    ike_alg_add((struct ike_alg *) &crypto_encryptor_3des);
    ike_alg_add((struct ike_alg *) &crypto_hasher_sha1);
    ike_alg_add((struct ike_alg *) &crypto_hasher_md5);
    ike_alg_init();
}

/* Oakley group description
 *
 * See RFC2409 "The Internet key exchange (IKE)" 6.
 */

const struct oakley_group_desc unset_group = {0, NULL, 0};	/* magic signifier */

const struct oakley_group_desc oakley_group[OAKLEY_GROUP_SIZE] = {
#   define BYTES(bits) (((bits) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)
    { OAKLEY_GROUP_MODP1024, &modp1024_modulus, BYTES(1024) },
    { OAKLEY_GROUP_MODP1536, &modp1536_modulus, BYTES(1536) },
    { OAKLEY_GROUP_MODP2048, &modp2048_modulus, BYTES(2048) },
    { OAKLEY_GROUP_MODP3072, &modp3072_modulus, BYTES(3072) },
    { OAKLEY_GROUP_MODP4096, &modp4096_modulus, BYTES(4096) },
    { OAKLEY_GROUP_MODP6144, &modp6144_modulus, BYTES(6144) },
    { OAKLEY_GROUP_MODP8192, &modp8192_modulus, BYTES(8192) },
#   undef BYTES
};

const struct oakley_group_desc *
lookup_group(u_int16_t group)
{
    int i;

    for (i = 0; i != elemsof(oakley_group); i++)
	if (group == oakley_group[i].group)
	    return &oakley_group[i];
    return NULL;
}

/* Encryption Routines
 *
 * Each uses and updates the state object's st_new_iv.
 * This must already be initialized.
 */

/* encrypt or decrypt part of an IKE message using DES
 * See RFC 2409 "IKE" Appendix B
 */
static void __attribute__ ((unused))
do_des(bool enc, void *buf, size_t buf_len, struct state *st)
{
    des_key_schedule ks;

    (void) des_set_key((des_cblock *)st->st_enc_key.ptr, ks);

    passert(st->st_new_iv_len >= DES_CBC_BLOCK_SIZE);
    st->st_new_iv_len = DES_CBC_BLOCK_SIZE;	/* truncate */

    des_ncbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
	ks,
	(des_cblock *)st->st_new_iv, enc);
}

/* encrypt or decrypt part of an IKE message using 3DES
 * See RFC 2409 "IKE" Appendix B
 */
static void
do_3des(u_int8_t *buf, size_t buf_len, u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
    des_key_schedule ks[3];

    passert (!key_size || (key_size==(DES_CBC_BLOCK_SIZE * 3)))
    (void) des_set_key((des_cblock *)key + 0, ks[0]);
    (void) des_set_key((des_cblock *)key + 1, ks[1]);
    (void) des_set_key((des_cblock *)key + 2, ks[2]);

    des_ede3_cbc_encrypt((des_cblock *)buf, (des_cblock *)buf, buf_len,
	ks[0], ks[1], ks[2],
	(des_cblock *)iv, enc);
}

/* hash and prf routines */
void
crypto_cbc_encrypt(const struct encrypt_desc *e, bool enc, u_int8_t *buf, size_t size, struct state *st)
{
    passert(st->st_new_iv_len >= e->enc_blocksize);
    st->st_new_iv_len = e->enc_blocksize;	/* truncate */

    e->do_crypt(buf, size, st->st_enc_key.ptr, st->st_enc_key.len, st->st_new_iv, enc);
    /*
    e->set_key(&ctx, st->st_enc_key.ptr, st->st_enc_key.len);
    e->cbc_crypt(&ctx, buf, size, st->st_new_iv, enc);
    */
}

/* HMAC package
 * rfc2104.txt specifies how HMAC works.
 */

void
hmac_init(struct hmac_ctx *ctx,
    const struct hash_desc *h,
    const u_char *key, size_t key_len)
{
    int k;

    ctx->h = h;
    ctx->hmac_digest_size = h->hash_digest_size;

    /* Prepare the two pads for the HMAC */

    memset(ctx->buf1, '\0', HMAC_BUFSIZE);

    if (key_len <= HMAC_BUFSIZE)
    {
	memcpy(ctx->buf1, key, key_len);
    }
    else
    {
	h->hash_init(&ctx->hash_ctx);
	h->hash_update(&ctx->hash_ctx, key, key_len);
	h->hash_final(ctx->buf1, &ctx->hash_ctx);
    }

    memcpy(ctx->buf2, ctx->buf1, HMAC_BUFSIZE);

    for (k = 0; k < HMAC_BUFSIZE; k++)
    {
	ctx->buf1[k] ^= HMAC_IPAD;
	ctx->buf2[k] ^= HMAC_OPAD;
    }

    hmac_reinit(ctx);
}

void
hmac_reinit(struct hmac_ctx *ctx)
{
    ctx->h->hash_init(&ctx->hash_ctx);
    ctx->h->hash_update(&ctx->hash_ctx, ctx->buf1, HMAC_BUFSIZE);
}

void
hmac_update(struct hmac_ctx *ctx,
    const u_char *data, size_t data_len)
{
    ctx->h->hash_update(&ctx->hash_ctx, data, data_len);
}

void
hmac_final(u_char *output, struct hmac_ctx *ctx)
{
    const struct hash_desc *h = ctx->h;

    h->hash_final(output, &ctx->hash_ctx);

    h->hash_init(&ctx->hash_ctx);
    h->hash_update(&ctx->hash_ctx, ctx->buf2, HMAC_BUFSIZE);
    h->hash_update(&ctx->hash_ctx, output, h->hash_digest_size);
    h->hash_final(output, &ctx->hash_ctx);
}
