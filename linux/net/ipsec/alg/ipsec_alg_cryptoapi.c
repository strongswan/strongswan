/*
 * ipsec_alg to linux cryptoapi GLUE
 *
 * Authors: CODE.ar TEAM
 * 	Harpo MAxx <harpo@linuxmendoza.org.ar>
 * 	JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 	Luciano Ruete <docemeses@softhome.net>
 * 
 * $Id: ipsec_alg_cryptoapi.c,v 1.3 2004/09/17 18:57:30 as Exp $
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
 * Example usage:
 *   modinfo -p ipsec_cryptoapi   (quite useful info, including supported algos)
 *   modprobe ipsec_cryptoapi
 *   modprobe ipsec_cryptoapi test=1
 *   modprobe ipsec_cryptoapi excl=1                     (exclusive cipher/algo)
 *   modprobe ipsec_cryptoapi noauto=1  aes=1 twofish=1  (only these ciphers)
 *   modprobe ipsec_cryptoapi aes=128,128                (force these keylens)
 *   modprobe ipsec_cryptoapi des_ede3=0                 (everything but 3DES)
 */
#include <linux/config.h>
#include <linux/version.h>

/*	
 *	special case: ipsec core modular with this static algo inside:
 *	must avoid MODULE magic for this file
 */
#if CONFIG_IPSEC_MODULE && CONFIG_IPSEC_ALG_CRYPTOAPI
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

/* warn the innocent */
#if !defined (CONFIG_CRYPTO) && !defined (CONFIG_CRYPTO_MODULE)
#warning "No linux CryptoAPI found, install 2.4.22+ or 2.6.x"
#define NO_CRYPTOAPI_SUPPORT
#endif
/*	Low freeswan header coupling	*/
#include "freeswan/ipsec_alg.h"

#include <linux/crypto.h>
#ifdef CRYPTO_API_VERSION_CODE
#warning "Old CryptoAPI is not supported. Only linux-2.4.22+ or linux-2.6.x are supported"
#define NO_CRYPTOAPI_SUPPORT
#endif

#ifdef NO_CRYPTOAPI_SUPPORT
#warning "Building an unusable module :P"
/* Catch old CryptoAPI by not allowing module to load */
IPSEC_ALG_MODULE_INIT( ipsec_cryptoapi_init )
{
	printk(KERN_WARNING "ipsec_cryptoapi.o was not built on stock Linux CryptoAPI (2.4.22+ or 2.6.x), not loading.\n");
	return -EINVAL;
}
#else
#include <asm/scatterlist.h>
#include <asm/pgtable.h>
#include <linux/mm.h>

#define CIPHERNAME_AES		"aes"
#define CIPHERNAME_3DES		"des3_ede"
#define CIPHERNAME_BLOWFISH	"blowfish"
#define CIPHERNAME_CAST		"cast5"
#define CIPHERNAME_SERPENT	"serpent"
#define CIPHERNAME_TWOFISH	"twofish"

#define ESP_3DES		3
#define ESP_AES			12
#define ESP_BLOWFISH		7	/* truly _constant_ :)  */
#define ESP_CAST		6	/* quite constant :) */
#define ESP_SERPENT		252	/* from ipsec drafts */
#define ESP_TWOFISH		253	/* from ipsec drafts */

#define AH_MD5			2
#define AH_SHA			3
#define DIGESTNAME_MD5		"md5"
#define DIGESTNAME_SHA1		"sha1"

MODULE_AUTHOR("Juanjo Ciarlante, Harpo MAxx, Luciano Ruete");
static int debug=0;
MODULE_PARM(debug, "i");
static int test=0;
MODULE_PARM(test, "i");
static int excl=0;
MODULE_PARM(excl, "i");

static int noauto = 0;
MODULE_PARM(noauto,"i");
MODULE_PARM_DESC(noauto, "Dont try all known algos, just setup enabled ones");

static int des_ede3[] = {-1, -1};
static int aes[] = {-1, -1};
static int blowfish[] = {-1, -1};
static int cast[] = {-1, -1};
static int serpent[] = {-1, -1};
static int twofish[] = {-1, -1};

MODULE_PARM(des_ede3,"1-2i");
MODULE_PARM(aes,"1-2i");
MODULE_PARM(blowfish,"1-2i");
MODULE_PARM(cast,"1-2i");
MODULE_PARM(serpent,"1-2i");
MODULE_PARM(twofish,"1-2i");
MODULE_PARM_DESC(des_ede3, "0: disable | 1: force_enable | min,max: dontuse");
MODULE_PARM_DESC(aes, "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(blowfish, "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(cast, "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(serpent, "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(twofish, "0: disable | 1: force_enable | min,max: keybitlens");

struct ipsec_alg_capi_cipher {
	const char *ciphername;	/* cryptoapi's ciphername */
	unsigned blocksize;
	unsigned short minbits;
	unsigned short maxbits;
	int *parm;		/* lkm param for this cipher */
	struct ipsec_alg_enc alg;	/* note it's not a pointer */
};
static struct ipsec_alg_capi_cipher alg_capi_carray[] = {
	{ CIPHERNAME_AES ,     16, 128, 256, aes    , { ixt_alg_id: ESP_AES, }},
	{ CIPHERNAME_TWOFISH , 16, 128, 256, twofish, { ixt_alg_id: ESP_TWOFISH, }},
	{ CIPHERNAME_SERPENT , 16, 128, 256, serpent, { ixt_alg_id: ESP_SERPENT, }},
	{ CIPHERNAME_CAST ,     8, 128, 128, cast   , { ixt_alg_id: ESP_CAST, }},
	{ CIPHERNAME_BLOWFISH , 8, 128, 448, blowfish,{ ixt_alg_id: ESP_BLOWFISH, }},
	{ CIPHERNAME_3DES ,     8, 192, 192, des_ede3,{ ixt_alg_id: ESP_3DES, }},
	{ NULL, 0, 0, 0, NULL, {} }
};
#ifdef NOT_YET
struct ipsec_alg_capi_digest {
	const char *digestname;	/* cryptoapi's digestname */
	struct digest_implementation *di;
	struct ipsec_alg_auth alg;	/* note it's not a pointer */
};
static struct ipsec_alg_capi_cipher alg_capi_darray[] = {
	{ DIGESTNAME_MD5,     NULL, { ixt_alg_id: AH_MD5, }},
	{ DIGESTNAME_SHA1,    NULL, { ixt_alg_id: AH_SHA, }},
	{ NULL, NULL, {} }
};
#endif
/*
 * 	"generic" linux cryptoapi setup_cipher() function
 */
int setup_cipher(const char *ciphername)
{
	return crypto_alg_available(ciphername, 0);
}

/*
 * 	setups ipsec_alg_capi_cipher "hyper" struct components, calling
 * 	register_ipsec_alg for cointaned ipsec_alg object
 */
static void _capi_destroy_key (struct ipsec_alg_enc *alg, __u8 *key_e);
static __u8 * _capi_new_key (struct ipsec_alg_enc *alg, const __u8 *key, size_t keylen);
static int _capi_cbc_encrypt(struct ipsec_alg_enc *alg, __u8 * key_e, __u8 * in, int ilen, const __u8 * iv, int encrypt);

static int
setup_ipsec_alg_capi_cipher(struct ipsec_alg_capi_cipher *cptr)
{
	int ret;
	cptr->alg.ixt_version = IPSEC_ALG_VERSION;
	cptr->alg.ixt_module = THIS_MODULE;
	atomic_set (& cptr->alg.ixt_refcnt, 0);
	strncpy (cptr->alg.ixt_name , cptr->ciphername, sizeof (cptr->alg.ixt_name));

	cptr->alg.ixt_blocksize=cptr->blocksize;
	cptr->alg.ixt_keyminbits=cptr->minbits;
	cptr->alg.ixt_keymaxbits=cptr->maxbits;
	cptr->alg.ixt_state = 0;
	if (excl) cptr->alg.ixt_state |= IPSEC_ALG_ST_EXCL;
	cptr->alg.ixt_e_keylen=cptr->alg.ixt_keymaxbits/8;
	cptr->alg.ixt_e_ctx_size = 0;
	cptr->alg.ixt_alg_type = IPSEC_ALG_TYPE_ENCRYPT;
	cptr->alg.ixt_e_new_key = _capi_new_key;
	cptr->alg.ixt_e_destroy_key = _capi_destroy_key;
	cptr->alg.ixt_e_cbc_encrypt = _capi_cbc_encrypt;
	cptr->alg.ixt_data = cptr;

	ret=register_ipsec_alg_enc(&cptr->alg);
	printk("setup_ipsec_alg_capi_cipher(): " 
			"alg_type=%d alg_id=%d name=%s "
			"keyminbits=%d keymaxbits=%d, ret=%d\n", 
				cptr->alg.ixt_alg_type, 
				cptr->alg.ixt_alg_id, 
				cptr->alg.ixt_name, 
				cptr->alg.ixt_keyminbits,
				cptr->alg.ixt_keymaxbits,
				ret);
	return ret;
}
/*
 * 	called in ipsec_sa_wipe() time, will destroy key contexts
 * 	and do 1 unbind()
 */
static void 
_capi_destroy_key (struct ipsec_alg_enc *alg, __u8 *key_e)
{
	struct crypto_tfm *tfm=(struct crypto_tfm*)key_e;
	
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug: _capi_destroy_key:"
				"name=%s key_e=%p \n",
				alg->ixt_name, key_e);
	if (!key_e) {
		printk(KERN_ERR "klips_debug: _capi_destroy_key:"
				"name=%s NULL key_e!\n",
				alg->ixt_name);
		return;
	}
	crypto_free_tfm(tfm);
}
	
/*
 * 	create new key context, need alg->ixt_data to know which
 * 	(of many) cipher inside this module is the target
 */
static __u8 *
_capi_new_key (struct ipsec_alg_enc *alg, const __u8 *key, size_t keylen)
{
	struct ipsec_alg_capi_cipher *cptr;
	struct crypto_tfm *tfm=NULL;

	cptr = alg->ixt_data;
	if (!cptr) {
		printk(KERN_ERR "_capi_new_key(): "
				"NULL ixt_data (?!) for \"%s\" algo\n" 
				, alg->ixt_name);
		goto err;
	}
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug:_capi_new_key:"
				"name=%s cptr=%p key=%p keysize=%d\n",
				alg->ixt_name, cptr, key, keylen);
	
	/*	
	 *	alloc tfm
	 */
	tfm = crypto_alloc_tfm(cptr->ciphername, CRYPTO_TFM_MODE_CBC);
	if (!tfm) {
		printk(KERN_ERR "_capi_new_key(): "
				"NULL tfm for \"%s\" cryptoapi (\"%s\") algo\n" 
			, alg->ixt_name, cptr->ciphername);
		goto err;
	}
	if (crypto_cipher_setkey(tfm, key, keylen) < 0) {
		printk(KERN_ERR "_capi_new_key(): "
				"failed new_key() for \"%s\" cryptoapi algo (keylen=%d)\n" 
			, alg->ixt_name, keylen);
		crypto_free_tfm(tfm);
		tfm=NULL;
	}
err:
	if (debug > 0)
		printk(KERN_DEBUG "klips_debug:_capi_new_key:"
				"name=%s key=%p keylen=%d tfm=%p\n",
				alg->ixt_name, key, keylen, tfm);
	return (__u8 *) tfm;
}
/*
 * 	core encryption function: will use cx->ci to call actual cipher's
 * 	cbc function
 */
static int 
_capi_cbc_encrypt(struct ipsec_alg_enc *alg, __u8 * key_e, __u8 * in, int ilen, const __u8 * iv, int encrypt) {
	int error =0;
	struct crypto_tfm *tfm=(struct crypto_tfm *)key_e;
	struct scatterlist sg = { 
		.page = virt_to_page(in),
		.offset = (unsigned long)(in) % PAGE_SIZE,
		.length=ilen,
	};
	if (debug > 1)
		printk(KERN_DEBUG "klips_debug:_capi_cbc_encrypt:"
				"key_e=%p "
				"in=%p out=%p ilen=%d iv=%p encrypt=%d\n"
				, key_e
				, in, in, ilen, iv, encrypt);
	crypto_cipher_set_iv(tfm, iv, crypto_tfm_alg_ivsize(tfm));
	if (encrypt)
		error = crypto_cipher_encrypt (tfm, &sg, &sg, ilen);
	else
		error = crypto_cipher_decrypt (tfm, &sg, &sg, ilen);
	if (debug > 1)
		printk(KERN_DEBUG "klips_debug:_capi_cbc_encrypt:"
				"error=%d\n"
				, error);
	return (error<0)? error : ilen;
}
/*
 * 	main initialization loop: for each cipher in list, do
 * 	1) setup cryptoapi cipher else continue
 * 	2) register ipsec_alg object
 */
static int
setup_cipher_list (struct ipsec_alg_capi_cipher* clist) 
{
	struct ipsec_alg_capi_cipher *cptr;
	/* foreach cipher in list ... */
	for (cptr=clist;cptr->ciphername;cptr++) {
		/* 
		 * see if cipher has been disabled (0) or
		 * if noauto set and not enabled (1)
		 */
		if (cptr->parm[0] == 0 || (noauto && cptr->parm[0] < 0)) {
			if (debug>0)
				printk(KERN_INFO "setup_cipher_list(): "
					"ciphername=%s skipped at user request: "
					"noauto=%d parm[0]=%d parm[1]=%d\n"
					, cptr->ciphername
					, noauto
					, cptr->parm[0]
					, cptr->parm[1]);
			continue;
		}
		/* 
		 * 	use a local ci to avoid touching cptr->ci,
		 * 	if register ipsec_alg success then bind cipher
		 */
		if( setup_cipher(cptr->ciphername) ) {
			if (debug > 0)
				printk(KERN_DEBUG "klips_debug:"
						"setup_cipher_list():"
						"ciphername=%s found\n"
				, cptr->ciphername);
			if (setup_ipsec_alg_capi_cipher(cptr) == 0) {
				
				
			} else {
				printk(KERN_ERR "klips_debug:"
						"setup_cipher_list():"
						"ciphername=%s failed ipsec_alg_register\n"
				, cptr->ciphername);
			}
		} else {
			if (debug>0)
				printk(KERN_INFO "setup_cipher_list(): lookup for ciphername=%s: not found \n",
				cptr->ciphername);
		}
	}
	return 0;
}
/*
 * 	deregister ipsec_alg objects and unbind ciphers
 */
static int
unsetup_cipher_list (struct ipsec_alg_capi_cipher* clist) 
{
	struct ipsec_alg_capi_cipher *cptr;
	/* foreach cipher in list ... */
	for (cptr=clist;cptr->ciphername;cptr++) {
		if (cptr->alg.ixt_state & IPSEC_ALG_ST_REGISTERED) {
			unregister_ipsec_alg_enc(&cptr->alg);
		}
	}
	return 0;
}
/*
 * 	test loop for registered algos
 */
static int
test_cipher_list (struct ipsec_alg_capi_cipher* clist) 
{
	int test_ret;
	struct ipsec_alg_capi_cipher *cptr;
	/* foreach cipher in list ... */
	for (cptr=clist;cptr->ciphername;cptr++) {
		if (cptr->alg.ixt_state & IPSEC_ALG_ST_REGISTERED) {
			test_ret=ipsec_alg_test(
					cptr->alg.ixt_alg_type,
					cptr->alg.ixt_alg_id, 
					test);
			printk("test_cipher_list(alg_type=%d alg_id=%d): test_ret=%d\n", 
					cptr->alg.ixt_alg_type, 
					cptr->alg.ixt_alg_id, 
					test_ret);
		}
	}
	return 0;
}

IPSEC_ALG_MODULE_INIT( ipsec_cryptoapi_init )
{
	int ret, test_ret;
	if ((ret=setup_cipher_list(alg_capi_carray)) < 0)
		return  -EPROTONOSUPPORT;
	if (ret==0 && test) {
		test_ret=test_cipher_list(alg_capi_carray);
	}
	return ret;
}
IPSEC_ALG_MODULE_EXIT( ipsec_cryptoapi_fini )
{
	unsetup_cipher_list(alg_capi_carray);
	return;
}
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

EXPORT_NO_SYMBOLS;
#endif /* NO_CRYPTOAPI_SUPPORT */
