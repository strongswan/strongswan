/*
 * Modular extensions service and registration functions interface
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * $Id$
 *
 */
/*
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
#ifndef IPSEC_ALG_H
#define IPSEC_ALG_H

/* 
 *   gcc >= 3.2 has removed __FUNCTION__, replaced by C99 __func__
 *   *BUT* its a compiler variable.
 */
#if (__GNUC__ >= 3)
#ifndef __FUNCTION__
#define __FUNCTION__ __func__
#endif
#endif

/*	Version 0.8.1-0 */
#define IPSEC_ALG_VERSION	0x00080100

#include <linux/types.h>
#include <linux/list.h>
#include <asm/atomic.h>
/*	
 *	The following structs are used via pointers in ipsec_alg object to
 *	avoid ipsec_alg.h coupling with freeswan headers, thus simplifying
 *	module development
 */
struct ipsec_sa;
struct esp;

/**************************************
 *
 *	Main registration object 
 *
 *************************************/
#define IPSEC_ALG_VERSION_QUAD(v)	\
	(v>>24),((v>>16)&0xff),((v>>8)&0xff),(v&0xff)
/*	
 *	Main ipsec_alg objects: "OOPrograming wannabe"
 *	Hierachy (carefully handled with _minimal_ cast'ing):
 *
 *      ipsec_alg+
 *		 +->ipsec_alg_enc  (ixt_alg_type=SADB_EXT_SUPPORTED_ENCRYPT)
 *		 +->ipsec_alg_auth (ixt_alg_type=SADB_EXT_SUPPORTED_AUTH)
 */

/***************************************************************
 *
 * 	INTERFACE object: struct ipsec_alg
 *
 ***************************************************************/

/* 
 * 	common part for every struct ipsec_alg_*	
 * 	(sortof poor's man OOP)
 */
#define IPSEC_ALG_STRUCT_COMMON \
	unsigned ixt_version;	/* only allow this version (or 'near')*/ \
	struct list_head ixt_list;	/* dlinked list */ \
	struct module *ixt_module;	/* THIS_MODULE */ \
	unsigned ixt_state;		/* state flags */ \
	atomic_t ixt_refcnt; 	/* ref. count when pointed from ipsec_sa */ \
	char ixt_name[16];	/* descriptive short name, eg. "3des" */ \
	void *ixt_data;		/* private for algo implementation */ \
	uint8_t  ixt_blocksize;	/* blocksize in bytes */ \
	\
	/* THIS IS A COPY of struct supported (lib/pfkey.h)        \
	 * please keep in sync until we migrate 'supported' stuff  \
	 * to ipsec_alg \
	 */ \
	uint16_t ixt_alg_type;	/* correspond to IPSEC_ALG_{ENCRYPT,AUTH} */ \
	uint8_t  ixt_alg_id;	/* enc. alg. number, eg. ESP_3DES */ \
	uint8_t  ixt_ivlen;	/* ivlen in bits, expected to be multiple of 8! */ \
	uint16_t ixt_keyminbits;/* min. keybits (of entropy) */ \
	uint16_t ixt_keymaxbits;/* max. keybits (of entropy) */

#define ixt_support ixt_alg_type
	
#define IPSEC_ALG_ST_SUPP	0x01
#define IPSEC_ALG_ST_REGISTERED 0x02
#define IPSEC_ALG_ST_EXCL	0x04
struct ipsec_alg {
	IPSEC_ALG_STRUCT_COMMON
};
/* 
 * 	Note the const in cbc_encrypt IV arg:
 * 	some ciphers like to toast passed IV (eg. 3DES): make a local IV copy
 */
struct ipsec_alg_enc {
	IPSEC_ALG_STRUCT_COMMON
	unsigned ixt_e_keylen;		/* raw key length in bytes          */
	unsigned ixt_e_ctx_size;	/* sa_p->key_e_size */
	int (*ixt_e_set_key)(struct ipsec_alg_enc *alg, __u8 *key_e, const __u8 *key, size_t keysize);
	__u8 *(*ixt_e_new_key)(struct ipsec_alg_enc *alg, const __u8 *key, size_t keysize);
	void (*ixt_e_destroy_key)(struct ipsec_alg_enc *alg, __u8 *key_e);
	int (*ixt_e_cbc_encrypt)(struct ipsec_alg_enc *alg, __u8 *key_e, __u8 *in, int ilen, const __u8 *iv, int encrypt);
};
struct ipsec_alg_auth {
	IPSEC_ALG_STRUCT_COMMON
	unsigned ixt_a_keylen;		/* raw key length in bytes          */
	unsigned ixt_a_ctx_size;	/* sa_p->key_a_size */
	unsigned ixt_a_authlen;		/* 'natural' auth. hash len (bytes) */
	int (*ixt_a_hmac_set_key)(struct ipsec_alg_auth *alg, __u8 *key_a, const __u8 *key, int keylen);
	int (*ixt_a_hmac_hash)(struct ipsec_alg_auth *alg, __u8 *key_a, const __u8 *dat, int len, __u8 *hash, int hashlen);
};
/*	
 *	These are _copies_ of SADB_EXT_SUPPORTED_{AUTH,ENCRYPT}, 
 *	to avoid header coupling for true constants
 *	about headers ... "cp is your friend" --Linus
 */
#define IPSEC_ALG_TYPE_AUTH	14
#define IPSEC_ALG_TYPE_ENCRYPT	15

/***************************************************************
 *
 * 	INTERFACE for module loading,testing, and unloading
 *
 ***************************************************************/
/*	-  registration calls 	*/
int register_ipsec_alg(struct ipsec_alg *);
int unregister_ipsec_alg(struct ipsec_alg *);
/*	-  optional (simple test) for algos 	*/
int ipsec_alg_test(unsigned alg_type, unsigned alg_id, int testparm);
/*	inline wrappers (usefull for type validation */
static inline int register_ipsec_alg_enc(struct ipsec_alg_enc *ixt) {
	return register_ipsec_alg((struct ipsec_alg*)ixt);
}
static inline int unregister_ipsec_alg_enc(struct ipsec_alg_enc *ixt) {
	return unregister_ipsec_alg((struct ipsec_alg*)ixt);
}
static inline int register_ipsec_alg_auth(struct ipsec_alg_auth *ixt) {
	return register_ipsec_alg((struct ipsec_alg*)ixt);
}
static inline int unregister_ipsec_alg_auth(struct ipsec_alg_auth *ixt) {
	return unregister_ipsec_alg((struct ipsec_alg*)ixt);
}

/*****************************************************************
 *
 * 	INTERFACE for ENC services: key creation, encrypt function
 *
 *****************************************************************/

#define IPSEC_ALG_ENCRYPT 1
#define IPSEC_ALG_DECRYPT 0

/* 	encryption key context creation function */
int ipsec_alg_enc_key_create(struct ipsec_sa *sa_p);
/* 
 * 	ipsec_alg_esp_encrypt(): encrypt ilen bytes in idat returns
 * 	0 or ERR<0
 */
int ipsec_alg_esp_encrypt(struct ipsec_sa *sa_p, __u8 *idat, int ilen, const __u8 *iv, int action);

/***************************************************************
 *
 * 	INTERFACE for AUTH services: key creation, hash functions
 *
 ***************************************************************/
int ipsec_alg_auth_key_create(struct ipsec_sa *sa_p);
int ipsec_alg_sa_esp_hash(const struct ipsec_sa *sa_p, const __u8 *espp, int len, __u8 *hash, int hashlen) ;
#define ipsec_alg_sa_esp_update(c,k,l) ipsec_alg_sa_esp_hash(c,k,l,NULL,0)

/* only called from ipsec_init.c */
int ipsec_alg_init(void);

/* algo module glue for static algos */
void ipsec_alg_static_init(void);
typedef int (*ipsec_alg_init_func_t) (void);

/**********************************************
 *
 * 	INTERFACE for ipsec_sa init and wipe
 *
 **********************************************/

/* returns true if ipsec_sa has ipsec_alg obj attached */
/* 
 * Initializes ipsec_sa's ipsec_alg object, using already loaded
 * proto, authalg, encalg.; links ipsec_alg objects (enc, auth)
 */
int ipsec_alg_sa_init(struct ipsec_sa *sa_p);
/* 
 * Destroys ipsec_sa's ipsec_alg object
 * unlinking ipsec_alg objects
 */
int ipsec_alg_sa_wipe(struct ipsec_sa *sa_p);

/**********************************************
 *
 * 	2.2 backport for some 2.4 useful module stuff
 *
 **********************************************/
#ifdef MODULE
#ifndef THIS_MODULE
#define THIS_MODULE          (&__this_module)
#endif
#ifndef module_init
typedef int (*__init_module_func_t)(void);
typedef void (*__cleanup_module_func_t)(void);

#define module_init(x) \
        int init_module(void) __attribute__((alias(#x))); \
        static inline __init_module_func_t __init_module_inline(void) \
        { return x; }
#define module_exit(x) \
        void cleanup_module(void) __attribute__((alias(#x))); \
        static inline __cleanup_module_func_t __cleanup_module_inline(void) \
        { return x; }
#endif

#define IPSEC_ALG_MODULE_INIT( func_name )	\
	static int func_name(void);		\
	module_init(func_name);			\
	static int __init func_name(void)
#define IPSEC_ALG_MODULE_EXIT( func_name )	\
	static void func_name(void);		\
	module_exit(func_name);			\
	static void __exit func_name(void)
#else	/* not MODULE */
#ifndef THIS_MODULE
#define THIS_MODULE          NULL
#endif
/*	
 *	I only want module_init() magic 
 *	when algo.c file *is THE MODULE*, in all other
 *	cases, initialization is called explicitely from ipsec_alg_init()
 */
#define IPSEC_ALG_MODULE_INIT( func_name )	\
	extern int func_name(void);		\
	int func_name(void)
#define IPSEC_ALG_MODULE_EXIT( func_name )	\
	extern void func_name(void);		\
	void func_name(void)
#endif

#endif /* IPSEC_ALG_H */
