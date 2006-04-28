/*
 * ipsec_alg SHA2 hash stubs
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 
 * $Id: ipsec_alg_sha2.c,v 1.2 2004/03/22 21:53:19 as Exp $
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
#include <linux/config.h>
#include <linux/version.h>

/*	
 *	special case: ipsec core modular with this static algo inside:
 *	must avoid MODULE magic for this file
 */
#if CONFIG_IPSEC_MODULE && CONFIG_IPSEC_ALG_SHA2
#undef MODULE
#endif

#include <linux/module.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/string.h>

/* Check if __exit is defined, if not null it */
#ifndef __exit
#define __exit
#endif

/*	Low freeswan header coupling	*/
#include "freeswan/ipsec_alg.h"
#include "libsha2/sha2.h"
#include "libsha2/hmac_sha2.h"

MODULE_AUTHOR("JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>");
static int debug=0;
MODULE_PARM(debug, "i");
static int test=0;
MODULE_PARM(test, "i");
static int excl=0;
MODULE_PARM(excl, "i");

/* almost constants ...: draft-ietf-ipsec-ciph-aes-cbc-03.txt */
#define AH_SHA2_256               5
#define AH_SHA2_384               6
#define AH_SHA2_512               7

static int _sha256_hmac_set_key(struct ipsec_alg_auth *alg, __u8 * key_a, const __u8 * key, int keylen) {
	sha256_hmac_context *hctx=(sha256_hmac_context*)(key_a);
	sha256_hmac_set_key(hctx, key, keylen);
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug: _sha256_hmac_set_key(): "
				"key_a=%p key=%p keysize=%d\n",
				key_a, key, keylen);
	return 0;
}
static int _sha256_hmac_hash(struct ipsec_alg_auth *alg, __u8 * key_a, const __u8 * dat, int len, __u8 * hash, int hashlen) {
	sha256_hmac_context *hctx=(sha256_hmac_context*)(key_a);
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug: _sha256_hmac_hash(): "
				"key_a=%p dat=%p len=%d hash=%p hashlen=%d\n",
				key_a, dat, len, hash, hashlen);
	sha256_hmac_hash(hctx, dat, len, hash, hashlen);
	return 0;
}
static int _sha512_hmac_set_key(struct ipsec_alg_auth *alg, __u8 * key_a, const __u8 * key, int keylen) {
	sha512_hmac_context *hctx=(sha512_hmac_context*)(key_a);
	sha512_hmac_set_key(hctx, key, keylen);
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug: _sha512_hmac_set_key(): "
				"key_a=%p key=%p keysize=%d\n",
				key_a, key, keylen);
	return 0;
}
static int _sha512_hmac_hash(struct ipsec_alg_auth *alg, __u8 * key_a, const __u8 * dat, int len, __u8 * hash, int hashlen) {
	sha512_hmac_context *hctx=(sha512_hmac_context*)(key_a);
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug: _sha512_hmac_hash(): "
				"key_a=%p dat=%p len=%d hash=%p hashlen=%d\n",
				key_a, dat, len, hash, hashlen);
	sha512_hmac_hash(hctx, dat, len, hash, hashlen);
	return 0;
}
static struct ipsec_alg_auth ipsec_alg_SHA2_256 = {
	ixt_version:	IPSEC_ALG_VERSION,
	ixt_module:	THIS_MODULE,
	ixt_refcnt:	ATOMIC_INIT(0),
	ixt_alg_type:	IPSEC_ALG_TYPE_AUTH,
	ixt_alg_id: 	AH_SHA2_256,
	ixt_name: 	"sha2_256",
	ixt_blocksize:	SHA256_BLOCKSIZE,
	ixt_keyminbits:	256,
	ixt_keymaxbits:	256,
	ixt_a_keylen:	256/8,
	ixt_a_ctx_size:	sizeof(sha256_hmac_context),
	ixt_a_hmac_set_key:	_sha256_hmac_set_key,
	ixt_a_hmac_hash:	_sha256_hmac_hash,
};
static struct ipsec_alg_auth ipsec_alg_SHA2_512 = {
	ixt_version:	IPSEC_ALG_VERSION,
	ixt_module:	THIS_MODULE,
	ixt_refcnt:	ATOMIC_INIT(0),
	ixt_alg_type:	IPSEC_ALG_TYPE_AUTH,
	ixt_alg_id: 	AH_SHA2_512,
	ixt_name: 	"sha2_512",
	ixt_blocksize:	SHA512_BLOCKSIZE,
	ixt_keyminbits:	512,
	ixt_keymaxbits:	512,
	ixt_a_keylen:	512/8,
	ixt_a_ctx_size:	sizeof(sha512_hmac_context),
	ixt_a_hmac_set_key:	_sha512_hmac_set_key,
	ixt_a_hmac_hash:	_sha512_hmac_hash,
};
	
IPSEC_ALG_MODULE_INIT( ipsec_sha2_init )
{
	int ret, test_ret;
	if (excl) ipsec_alg_SHA2_256.ixt_state |= IPSEC_ALG_ST_EXCL;
	ret=register_ipsec_alg_auth(&ipsec_alg_SHA2_256);
	printk("ipsec_sha2_init(alg_type=%d alg_id=%d name=%s): ret=%d\n", 
			ipsec_alg_SHA2_256.ixt_alg_type, 
			ipsec_alg_SHA2_256.ixt_alg_id, 
			ipsec_alg_SHA2_256.ixt_name, 
			ret);
	if (ret != 0) 
		goto out;
	if (ret==0 && test) {
		test_ret=ipsec_alg_test(
				ipsec_alg_SHA2_256.ixt_alg_type,
				ipsec_alg_SHA2_256.ixt_alg_id, 
				test);
		printk("ipsec_sha2_init(alg_type=%d alg_id=%d): test_ret=%d\n", 
				ipsec_alg_SHA2_256.ixt_alg_type, 
				ipsec_alg_SHA2_256.ixt_alg_id, 
				test_ret);
	}
	if (excl) ipsec_alg_SHA2_512.ixt_state |= IPSEC_ALG_ST_EXCL;
	ret=register_ipsec_alg_auth(&ipsec_alg_SHA2_512);
	printk("ipsec_sha2_init(alg_type=%d alg_id=%d name=%s): ret=%d\n", 
			ipsec_alg_SHA2_512.ixt_alg_type, 
			ipsec_alg_SHA2_512.ixt_alg_id, 
			ipsec_alg_SHA2_512.ixt_name, 
			ret);
	if (ret != 0) 
		goto out_256;
	if (ret==0 && test) {
		test_ret=ipsec_alg_test(
				ipsec_alg_SHA2_512.ixt_alg_type,
				ipsec_alg_SHA2_512.ixt_alg_id, 
				test);
		printk("ipsec_sha2_init(alg_type=%d alg_id=%d): test_ret=%d\n", 
				ipsec_alg_SHA2_512.ixt_alg_type, 
				ipsec_alg_SHA2_512.ixt_alg_id, 
				test_ret);
	}
	goto out;
out_256:
	unregister_ipsec_alg_auth(&ipsec_alg_SHA2_256);
out:
	return ret;
}
IPSEC_ALG_MODULE_EXIT( ipsec_sha2_fini )
{
	unregister_ipsec_alg_auth(&ipsec_alg_SHA2_512);
	unregister_ipsec_alg_auth(&ipsec_alg_SHA2_256);
	return;
}
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

EXPORT_NO_SYMBOLS;
