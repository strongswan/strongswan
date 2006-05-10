#ifndef _HMAC_GENERIC_H
#define _HMAC_GENERIC_H
/*
 * HMAC macro helpers
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 */

#ifndef DIVUP
#define DIVUP(x,y) ((x + y -1) / y) /* divide, rounding upwards */
#endif
#ifndef HMAC_IPAD
#define		HMAC_IPAD	0x36
#define		HMAC_OPAD	0x5C
#endif
#define HMAC_SET_KEY_IMPL(func_name, hctx_t, blocksize, func_init, func_update) \
void func_name(hctx_t *hctx, const u_int8_t * key, int keylen) { \
	int i;\
	u_int8_t kb[blocksize];		\
	for (i = 0; i < DIVUP(keylen*8, 8); i++) {	\
		kb[i] = key[i] ^ HMAC_IPAD;	\
	}					\
	for (; i < blocksize; i++) {		\
		kb[i] = HMAC_IPAD;		\
	}					\
	func_init(&hctx->ictx);			\
	func_update(&hctx->ictx, kb, blocksize);	\
	for (i = 0; i < blocksize; i++) {	\
		kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);	\
	}					\
	func_init(&hctx->octx);			\
	func_update(&hctx->octx, kb, blocksize);	\
}
#define HMAC_HASH_IMPL(func_name, hctx_t, ctx_t, ahlen, func_update, func_result ) \
void func_name(hctx_t *hctx, const u_int8_t * dat, int len, u_int8_t * hash, int hashlen) {	\
	ctx_t ctx;	\
	ctx=hctx->ictx;	\
	if (dat) func_update(&ctx, dat, len);	\
	if (hash) {				\
		u_int8_t hash_buf[ahlen];			\
		func_result(&ctx, hash_buf, ahlen);	\
		ctx=hctx->octx;				\
		func_update(&ctx, hash_buf, ahlen);	\
		func_result(&ctx, hash, hashlen);	\
		memset(&ctx, 0, sizeof (ctx));		\
		memset(&hash_buf, 0, sizeof (hash_buf));\
	}					\
}
#endif /* _HMAC_GENERIC_H */
