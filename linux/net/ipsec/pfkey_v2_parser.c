/*
 * @(#) RFC2367 PF_KEYv2 Key management API message parser
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
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
 * RCSID $Id: pfkey_v2_parser.c,v 1.4 2004/09/29 22:27:41 as Exp $
 */

/*
 *		Template from klips/net/ipsec/ipsec/ipsec_netlink.c.
 */

char pfkey_v2_parser_c_version[] = "$Id: pfkey_v2_parser.c,v 1.4 2004/09/29 22:27:41 as Exp $";

#include <linux/config.h>
#include <linux/version.h>
#include <linux/kernel.h> /* printk() */

#include "freeswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/skbuff.h>

#include <freeswan.h>

#include <crypto/des.h>

#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
# include <asm/uaccess.h>
# include <linux/in6.h>
# define ip_chk_addr inet_addr_type
# define IS_MYADDR RTN_LOCAL
#endif
#include <asm/checksum.h>
#include <net/ip.h>
#ifdef NETLINK_SOCK
# include <linux/netlink.h>
#else
# include <net/netlink.h>
#endif

#include <linux/random.h>	/* get_random_bytes() */

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_sa.h"

#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_ah.h"
#include "freeswan/ipsec_esp.h"
#include "freeswan/ipsec_tunnel.h"
#include "freeswan/ipsec_rcv.h"
#include "freeswan/ipcomp.h"

#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/ipsec_proto.h"
#include "freeswan/ipsec_alg.h"


#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

struct sklist_t {
	struct socket *sk;
	struct sklist_t* next;
} pfkey_sklist_head, *pfkey_sklist, *pfkey_sklist_prev;

__u32 pfkey_msg_seq = 0;

int
pfkey_alloc_eroute(struct eroute** eroute)
{
	int error = 0;
	if(*eroute) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_alloc_eroute: "
			    "eroute struct already allocated\n");
		SENDERR(EEXIST);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_alloc_eroute: "
		    "allocating %lu bytes for an eroute.\n",
		    (unsigned long) sizeof(**eroute));
	if((*eroute = kmalloc(sizeof(**eroute), GFP_ATOMIC) ) == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_alloc_eroute: "
			    "memory allocation error\n");
		SENDERR(ENOMEM);
	}
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_alloc_eroute: "
		    "allocated eroute struct=0p%p.\n", eroute);
	memset((caddr_t)*eroute, 0, sizeof(**eroute));
	(*eroute)->er_eaddr.sen_len =
		(*eroute)->er_emask.sen_len = sizeof(struct sockaddr_encap);
	(*eroute)->er_eaddr.sen_family =
		(*eroute)->er_emask.sen_family = AF_ENCAP;
	(*eroute)->er_eaddr.sen_type = SENT_IP4;
	(*eroute)->er_emask.sen_type = 255;
	(*eroute)->er_pid = 0;
	(*eroute)->er_count = 0;
	(*eroute)->er_lasttime = jiffies/HZ;

 errlab:
	return(error);
}

DEBUG_NO_STATIC int
pfkey_x_protocol_process(struct sadb_ext *pfkey_ext,
			 struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_protocol * p = (struct sadb_protocol *)pfkey_ext;

	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_protocol_process: %p\n", extr);

	if (extr == 0) {
		KLIPS_PRINT(debug_pfkey,
                         "klips_debug:pfkey_x_protocol_process:"
			    "extr is NULL, fatal\n");
		SENDERR(EINVAL);
	}
	if (extr->eroute == 0) {
		KLIPS_PRINT(debug_pfkey,
                        "klips_debug:pfkey_x_protocol_process:"
			    "extr->eroute is NULL, fatal\n");
		SENDERR(EINVAL);
	}
	extr->eroute->er_eaddr.sen_proto = p->sadb_protocol_proto;
	extr->eroute->er_emask.sen_proto = p->sadb_protocol_proto ? ~0:0;
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_protocol_process: protocol = %d.\n",
		    p->sadb_protocol_proto);
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_ipsec_sa_init(struct ipsec_sa *ipsp, struct sadb_ext **extensions)
{
        int error = 0;
        char sa[SATOA_BUF];
	size_t sa_len;
	char ipaddr_txt[ADDRTOA_BUF];
	char ipaddr2_txt[ADDRTOA_BUF];
#if defined (CONFIG_IPSEC_AUTH_HMAC_MD5) || defined (CONFIG_IPSEC_AUTH_HMAC_SHA1)
        int i;
	unsigned char kb[AHMD596_BLKLEN];
#endif
#ifdef CONFIG_IPSEC_ALG
	struct ipsec_alg_enc *ixt_e = NULL;
	struct ipsec_alg_auth *ixt_a = NULL;
#endif /* CONFIG_IPSEC_ALG */

	if(ipsp == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_ipsec_sa_init: "
			    "ipsp is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	sa_len = satoa(ipsp->ips_said, 0, sa, SATOA_BUF);

        KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_ipsec_sa_init: "
		    "(pfkey defined) called for SA:%s\n",
		    sa_len ? sa : " (error)");

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_ipsec_sa_init: "
		    "calling init routine of %s%s%s\n",
		    IPS_XFORM_NAME(ipsp));
	
	switch(ipsp->ips_said.proto) {
		
#ifdef CONFIG_IPSEC_IPIP
	case IPPROTO_IPIP: {
		addrtoa(((struct sockaddr_in*)(ipsp->ips_addr_s))->sin_addr,
			0,
			ipaddr_txt, sizeof(ipaddr_txt));
		addrtoa(((struct sockaddr_in*)(ipsp->ips_addr_d))->sin_addr,
			0,
			ipaddr2_txt, sizeof(ipaddr_txt));
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_ipsec_sa_init: "
			    "(pfkey defined) IPIP ipsec_sa set for %s->%s.\n",
			    ipaddr_txt,
			    ipaddr2_txt);
	}
	break;
#endif /* !CONFIG_IPSEC_IPIP */
#ifdef CONFIG_IPSEC_AH
	case IPPROTO_AH:
		switch(ipsp->ips_authalg) {
# ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
		case AH_MD5: {
			unsigned char *akp;
			unsigned int aks;
			MD5_CTX *ictx;
			MD5_CTX *octx;
			
			if(ipsp->ips_key_bits_a != (AHMD596_KLEN * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_ipsec_sa_init: "
					    "incorrect key size: %d bits -- must be %d bits\n"/*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_a, AHMD596_KLEN * 8);
				SENDERR(EINVAL);
			}
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "hmac md5-96 key is 0x%08x %08x %08x %08x\n",
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+0)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+1)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+2)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+3)));
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			
			ipsp->ips_auth_bits = AHMD596_ALEN * 8;
			
			/* save the pointer to the key material */
			akp = ipsp->ips_key_a;
			aks = ipsp->ips_key_a_size;
			
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
			           "klips_debug:pfkey_ipsec_sa_init: "
			           "allocating %lu bytes for md5_ctx.\n",
			           (unsigned long) sizeof(struct md5_ctx));
			if((ipsp->ips_key_a = (caddr_t)
			    kmalloc(sizeof(struct md5_ctx), GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_a = akp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_a_size = sizeof(struct md5_ctx);

			for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8); i++) {
				kb[i] = akp[i] ^ HMAC_IPAD;
			}
			for (; i < AHMD596_BLKLEN; i++) {
				kb[i] = HMAC_IPAD;
			}

			ictx = &(((struct md5_ctx*)(ipsp->ips_key_a))->ictx);
			MD5Init(ictx);
			MD5Update(ictx, kb, AHMD596_BLKLEN);

			for (i = 0; i < AHMD596_BLKLEN; i++) {
				kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);
			}

			octx = &(((struct md5_ctx*)(ipsp->ips_key_a))->octx);
			MD5Init(octx);
			MD5Update(octx, kb, AHMD596_BLKLEN);
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "MD5 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
				    ((__u32*)ictx)[0],
				    ((__u32*)ictx)[1],
				    ((__u32*)ictx)[2],
				    ((__u32*)ictx)[3],
				    ((__u32*)octx)[0],
				    ((__u32*)octx)[1],
				    ((__u32*)octx)[2],
				    ((__u32*)octx)[3] );
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			
			/* zero key buffer -- paranoid */
			memset(akp, 0, aks);
			kfree(akp);
		}
		break;
# endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
# ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
		case AH_SHA: {
			unsigned char *akp;
			unsigned int aks;
			SHA1_CTX *ictx;
			SHA1_CTX *octx;
			
			if(ipsp->ips_key_bits_a != (AHSHA196_KLEN * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_ipsec_sa_init: "
					    "incorrect key size: %d bits -- must be %d bits\n"/*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_a, AHSHA196_KLEN * 8);
				SENDERR(EINVAL);
			}
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "hmac sha1-96 key is 0x%08x %08x %08x %08x\n",
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+0)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+1)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+2)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+3)));
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			
			ipsp->ips_auth_bits = AHSHA196_ALEN * 8;
			
			/* save the pointer to the key material */
			akp = ipsp->ips_key_a;
			aks = ipsp->ips_key_a_size;
			
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
			            "klips_debug:pfkey_ipsec_sa_init: "
			            "allocating %lu bytes for sha1_ctx.\n",
			            (unsigned long) sizeof(struct sha1_ctx));
			if((ipsp->ips_key_a = (caddr_t)
			    kmalloc(sizeof(struct sha1_ctx), GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_a = akp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_a_size = sizeof(struct sha1_ctx);

			for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8); i++) {
				kb[i] = akp[i] ^ HMAC_IPAD;
			}
			for (; i < AHMD596_BLKLEN; i++) {
				kb[i] = HMAC_IPAD;
			}

			ictx = &(((struct sha1_ctx*)(ipsp->ips_key_a))->ictx);
			SHA1Init(ictx);
			SHA1Update(ictx, kb, AHSHA196_BLKLEN);

			for (i = 0; i < AHSHA196_BLKLEN; i++) {
				kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);
			}

			octx = &(((struct sha1_ctx*)(ipsp->ips_key_a))->octx);
			SHA1Init(octx);
			SHA1Update(octx, kb, AHSHA196_BLKLEN);
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "SHA1 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n", 
				    ((__u32*)ictx)[0],
				    ((__u32*)ictx)[1],
				    ((__u32*)ictx)[2],
				    ((__u32*)ictx)[3],
				    ((__u32*)octx)[0],
				    ((__u32*)octx)[1],
				    ((__u32*)octx)[2],
				    ((__u32*)octx)[3] );
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			/* zero key buffer -- paranoid */
			memset(akp, 0, aks);
			kfree(akp);
		}
		break;
# endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
		default:
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "authalg=%d support not available in the kernel",
				    ipsp->ips_authalg);
			SENDERR(EINVAL);
		}
	break;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_ESP
	case IPPROTO_ESP: {
#if defined (CONFIG_IPSEC_AUTH_HMAC_MD5) || defined (CONFIG_IPSEC_AUTH_HMAC_SHA1)
		unsigned char *akp;
		unsigned int aks;
#endif
#if defined (CONFIG_IPSEC_ENC_3DES)
		unsigned char *ekp;
		unsigned int eks;
#endif

		ipsp->ips_iv_size = 0;
#ifdef CONFIG_IPSEC_ALG
		if ((ixt_e=ipsp->ips_alg_enc)) {
			ipsp->ips_iv_size = ixt_e->ixt_ivlen/8;
		} else	
#endif /* CONFIG_IPSEC_ALG */
		switch(ipsp->ips_encalg) {
# ifdef CONFIG_IPSEC_ENC_3DES
		case ESP_3DES:
# endif /* CONFIG_IPSEC_ENC_3DES */
# if defined(CONFIG_IPSEC_ENC_3DES)
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
			            "klips_debug:pfkey_ipsec_sa_init: "
			            "allocating %u bytes for iv.\n",
			            EMT_ESPDES_IV_SZ);
			if((ipsp->ips_iv = (caddr_t)
			    kmalloc((ipsp->ips_iv_size = EMT_ESPDES_IV_SZ), GFP_ATOMIC)) == NULL) {
				SENDERR(ENOMEM);
			}
			prng_bytes(&ipsec_prng, (char *)ipsp->ips_iv, EMT_ESPDES_IV_SZ);
			ipsp->ips_iv_bits = ipsp->ips_iv_size * 8;
			ipsp->ips_iv_size = EMT_ESPDES_IV_SZ;
			break;
# endif /* defined(CONFIG_IPSEC_ENC_3DES) */
		case ESP_NONE:
			break;
		default:
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "encalg=%d support not available in the kernel",
				    ipsp->ips_encalg);
			SENDERR(EINVAL);
		}

		/* Create IV */
		if (ipsp->ips_iv_size) {
			if((ipsp->ips_iv = (caddr_t)
			    kmalloc(ipsp->ips_iv_size, GFP_ATOMIC)) == NULL) {
				SENDERR(ENOMEM);
			}
			prng_bytes(&ipsec_prng, (char *)ipsp->ips_iv, ipsp->ips_iv_size);
			ipsp->ips_iv_bits = ipsp->ips_iv_size * 8;
		}
		
#ifdef CONFIG_IPSEC_ALG
		if (ixt_e) {
			if ((error=ipsec_alg_enc_key_create(ipsp)) < 0)
				SENDERR(-error);
		} else
#endif /* CONFIG_IPSEC_ALG */
		switch(ipsp->ips_encalg) {
# ifdef CONFIG_IPSEC_ENC_3DES
		case ESP_3DES:
			if(ipsp->ips_key_bits_e != (EMT_ESP3DES_KEY_SZ * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_ipsec_sa_init: "
					    "incorrect encryption key size: %d bits -- must be %d bits\n"/*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_e, EMT_ESP3DES_KEY_SZ * 8);
				SENDERR(EINVAL);
			}
			
			/* save encryption key pointer */
			ekp = ipsp->ips_key_e;
			eks = ipsp->ips_key_e_size;
			
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
			            "klips_debug:pfkey_ipsec_sa_init: "
			            "allocating %lu bytes for 3des.\n",
			            (unsigned long) (3 * sizeof(struct des_eks)));
			if((ipsp->ips_key_e = (caddr_t)
			    kmalloc(3 * sizeof(struct des_eks), GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_e = ekp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_e_size = 3 * sizeof(struct des_eks);

			for(i = 0; i < 3; i++) {
#if KLIPS_DIVULGE_CYPHER_KEY
				KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
					    "klips_debug:pfkey_ipsec_sa_init: "
					    "3des key %d/3 is 0x%08x%08x\n",
					    i + 1,
					    ntohl(*((__u32 *)ekp + i * 2)),
					    ntohl(*((__u32 *)ekp + i * 2 + 1)));
#  endif
#if KLIPS_FIXES_DES_PARITY				
				/* force parity */
				des_set_odd_parity((des_cblock *)(ekp + EMT_ESPDES_KEY_SZ * i));
#endif
				error = des_set_key((des_cblock *)(ekp + EMT_ESPDES_KEY_SZ * i),
						    ((struct des_eks *)(ipsp->ips_key_e))[i].ks);
				if (error == -1)
					printk("klips_debug:pfkey_ipsec_sa_init: "
					       "parity error in des key %d/3\n",
					       i + 1);
				else if (error == -2)
					printk("klips_debug:pfkey_ipsec_sa_init: "
					       "illegal weak des key %d/3\n", i + 1);
				if (error) {
					memset(ekp, 0, eks);
					kfree(ekp);
					SENDERR(EINVAL);
				}
			}

			/* paranoid */
			memset(ekp, 0, eks);
			kfree(ekp);
			break;
# endif /* CONFIG_IPSEC_ENC_3DES */
                case ESP_NONE:
			break;
		default:
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "encalg=%d support not available in the kernel",
				    ipsp->ips_encalg);
			SENDERR(EINVAL);
		}

#ifdef CONFIG_IPSEC_ALG
		if ((ixt_a=ipsp->ips_alg_auth)) {
			if ((error=ipsec_alg_auth_key_create(ipsp)) < 0)
				SENDERR(-error);
		} else	
#endif /* CONFIG_IPSEC_ALG */
		
		switch(ipsp->ips_authalg) {
# ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
		case AH_MD5: {
			MD5_CTX *ictx;
			MD5_CTX *octx;

			if(ipsp->ips_key_bits_a != (AHMD596_KLEN * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_ipsec_sa_init: "
					    "incorrect authorisation key size: %d bits -- must be %d bits\n"/*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_a,
					    AHMD596_KLEN * 8);
				SENDERR(EINVAL);
			}
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "hmac md5-96 key is 0x%08x %08x %08x %08x\n",
				    ntohl(*(((__u32 *)(ipsp->ips_key_a))+0)),
				    ntohl(*(((__u32 *)(ipsp->ips_key_a))+1)),
				    ntohl(*(((__u32 *)(ipsp->ips_key_a))+2)),
				    ntohl(*(((__u32 *)(ipsp->ips_key_a))+3)));
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			ipsp->ips_auth_bits = AHMD596_ALEN * 8;
			
			/* save the pointer to the key material */
			akp = ipsp->ips_key_a;
			aks = ipsp->ips_key_a_size;
			
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
			            "klips_debug:pfkey_ipsec_sa_init: "
			            "allocating %lu bytes for md5_ctx.\n",
			            (unsigned long) sizeof(struct md5_ctx));
			if((ipsp->ips_key_a = (caddr_t)
			    kmalloc(sizeof(struct md5_ctx), GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_a = akp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_a_size = sizeof(struct md5_ctx);

			for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8); i++) {
				kb[i] = akp[i] ^ HMAC_IPAD;
			}
			for (; i < AHMD596_BLKLEN; i++) {
				kb[i] = HMAC_IPAD;
			}

			ictx = &(((struct md5_ctx*)(ipsp->ips_key_a))->ictx);
			MD5Init(ictx);
			MD5Update(ictx, kb, AHMD596_BLKLEN);

			for (i = 0; i < AHMD596_BLKLEN; i++) {
				kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);
			}

			octx = &(((struct md5_ctx*)(ipsp->ips_key_a))->octx);
			MD5Init(octx);
			MD5Update(octx, kb, AHMD596_BLKLEN);
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "MD5 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
				    ((__u32*)ictx)[0],
				    ((__u32*)ictx)[1],
				    ((__u32*)ictx)[2],
				    ((__u32*)ictx)[3],
				    ((__u32*)octx)[0],
				    ((__u32*)octx)[1],
				    ((__u32*)octx)[2],
				    ((__u32*)octx)[3] );
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			/* paranoid */
			memset(akp, 0, aks);
			kfree(akp);
			break;
		}
# endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
# ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
		case AH_SHA: {
			SHA1_CTX *ictx;
			SHA1_CTX *octx;

			if(ipsp->ips_key_bits_a != (AHSHA196_KLEN * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_ipsec_sa_init: "
					    "incorrect authorisation key size: %d bits -- must be %d bits\n"/*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_a,
					    AHSHA196_KLEN * 8);
				SENDERR(EINVAL);
			}
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "hmac sha1-96 key is 0x%08x %08x %08x %08x\n",
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+0)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+1)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+2)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a)+3)));
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			ipsp->ips_auth_bits = AHSHA196_ALEN * 8;
			
			/* save the pointer to the key material */
			akp = ipsp->ips_key_a;
			aks = ipsp->ips_key_a_size;

			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
			            "klips_debug:pfkey_ipsec_sa_init: "
			            "allocating %lu bytes for sha1_ctx.\n",
			            (unsigned long) sizeof(struct sha1_ctx));
			if((ipsp->ips_key_a = (caddr_t)
			    kmalloc(sizeof(struct sha1_ctx), GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_a = akp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_a_size = sizeof(struct sha1_ctx);

			for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8); i++) {
				kb[i] = akp[i] ^ HMAC_IPAD;
			}
			for (; i < AHMD596_BLKLEN; i++) {
				kb[i] = HMAC_IPAD;
			}

			ictx = &(((struct sha1_ctx*)(ipsp->ips_key_a))->ictx);
			SHA1Init(ictx);
			SHA1Update(ictx, kb, AHSHA196_BLKLEN);

			for (i = 0; i < AHSHA196_BLKLEN; i++) {
				kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);
			}

			octx = &((struct sha1_ctx*)(ipsp->ips_key_a))->octx;
			SHA1Init(octx);
			SHA1Update(octx, kb, AHSHA196_BLKLEN);
			
#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "SHA1 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
				    ((__u32*)ictx)[0],
				    ((__u32*)ictx)[1],
				    ((__u32*)ictx)[2],
				    ((__u32*)ictx)[3],
				    ((__u32*)octx)[0],
				    ((__u32*)octx)[1],
				    ((__u32*)octx)[2],
				    ((__u32*)octx)[3] );
#  endif /* KLIPS_DIVULGE_HMAC_KEY */
			memset(akp, 0, aks);
			kfree(akp);
			break;
		}
# endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
		case AH_NONE:
			break;
		default:
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_ipsec_sa_init: "
				    "authalg=%d support not available in the kernel.\n",
				    ipsp->ips_authalg);
			SENDERR(EINVAL);
		}
	}
			break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_IPCOMP
	case IPPROTO_COMP:
		ipsp->ips_comp_adapt_tries = 0;
		ipsp->ips_comp_adapt_skip = 0;
		ipsp->ips_comp_ratio_cbytes = 0;
		ipsp->ips_comp_ratio_dbytes = 0;
		break;
#endif /* CONFIG_IPSEC_IPCOMP */
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_ipsec_sa_init: "
			    "proto=%d unknown.\n",
			    ipsp->ips_said.proto);
		SENDERR(EINVAL);
	}
	
 errlab:
	return(error);
}


int
pfkey_safe_build(int error, struct sadb_ext *extensions[SADB_MAX+1])
{
	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_safe_build: "
		    "error=%d\n",
		    error);
	if (!error) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_safe_build:"
			    "success.\n");
		return 1;
	} else {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_safe_build:"
			    "caught error %d\n",
			    error);
		pfkey_extensions_free(extensions);
		return 0;
	}
}


DEBUG_NO_STATIC int
pfkey_getspi_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	ipsec_spi_t minspi = htonl(256), maxspi = htonl(-1L);
	int found_avail = 0;
	struct ipsec_sa *ipsq;
	char sa[SATOA_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_getspi_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if(extr == NULL || extr->ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_getspi_parse: "
			    "error, extr or extr->ipsec_sa pointer NULL\n");
		SENDERR(EINVAL);
	}

	if(extensions[SADB_EXT_SPIRANGE]) {
		minspi = ((struct sadb_spirange *)extensions[SADB_EXT_SPIRANGE])->sadb_spirange_min;
		maxspi = ((struct sadb_spirange *)extensions[SADB_EXT_SPIRANGE])->sadb_spirange_max;
	}

	if(maxspi == minspi) {
		extr->ips->ips_said.spi = maxspi;
		ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said));
		if(ipsq != NULL) {
			sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);
			ipsec_sa_put(ipsq);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_getspi_parse: "
				    "EMT_GETSPI found an old ipsec_sa for SA: %s, delete it first.\n",
				    sa_len ? sa : " (error)");
			SENDERR(EEXIST);
		} else {
			found_avail = 1;
		}
	} else {
		int i = 0;
		__u32 rand_val;
		__u32 spi_diff;
		while( ( i < (spi_diff = (ntohl(maxspi) - ntohl(minspi)))) && !found_avail ) {
			prng_bytes(&ipsec_prng, (char *) &(rand_val),
					 ( (spi_diff < (2^8))  ? 1 :
					   ( (spi_diff < (2^16)) ? 2 :
					     ( (spi_diff < (2^24)) ? 3 :
					   4 ) ) ) );
			extr->ips->ips_said.spi = htonl(ntohl(minspi) +
					      (rand_val %
					      (spi_diff + 1)));
			i++;
			ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said));
			if(ipsq == NULL) {
				found_avail = 1;
			} else {
				ipsec_sa_put(ipsq);
			}
		}
	}

	sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);

	if (!found_avail) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_getspi_parse: "
			    "found an old ipsec_sa for SA: %s, delete it first.\n",
			    sa_len ? sa : " (error)");
		SENDERR(EEXIST);
	}

	if(ip_chk_addr((unsigned long)extr->ips->ips_said.dst.s_addr) == IS_MYADDR) {
		extr->ips->ips_flags |= EMT_INBOUND;
	}
	
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_getspi_parse: "
		    "existing ipsec_sa not found (this is good) for SA: %s, %s-bound, allocating.\n",
		    sa_len ? sa : " (error)",
		    extr->ips->ips_flags & EMT_INBOUND ? "in" : "out");
	
	/* XXX extr->ips->ips_rcvif = &(enc_softc[em->em_if].enc_if);*/
	extr->ips->ips_rcvif = NULL;
	extr->ips->ips_life.ipl_addtime.ipl_count = jiffies/HZ;

	extr->ips->ips_state = SADB_SASTATE_LARVAL;

	if(!extr->ips->ips_life.ipl_allocations.ipl_count) {
		extr->ips->ips_life.ipl_allocations.ipl_count += 1;
	}

	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_GETSPI,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							0,
							SADB_SASTATE_LARVAL,
							0,
							0,
							0,
							extr->ips->ips_ref),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_SRC],
						     SADB_EXT_ADDRESS_SRC,
						     0, /*extr->ips->ips_said.proto,*/
						     0,
						     extr->ips->ips_addr_s),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
						     SADB_EXT_ADDRESS_DST,
						     0, /*extr->ips->ips_said.proto,*/
						     0,
						     extr->ips->ips_addr_d),
				 extensions_reply) )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "failed to build the getspi reply message extensions\n");
		goto errlab;
	}
	
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "failed to build the getspi reply message\n");
		SENDERR(-error);
	}
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
				    "sending up getspi reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "sending up getspi reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
	if((error = ipsec_sa_add(extr->ips))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "failed to add the larval SA=%s with error=%d.\n",
			    sa_len ? sa : " (error)",
			    error);
		SENDERR(-error);
	}
	extr->ips = NULL;
	
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_getspi_parse: "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");
	
 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_update_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	struct ipsec_sa* ipsq;
	char sa[SATOA_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	struct ipsec_sa *nat_t_ips_saved = NULL;
#endif
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if(((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_state != SADB_SASTATE_MATURE) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "error, sa_state=%d must be MATURE=%d\n",
			    ((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_state,
			    SADB_SASTATE_MATURE);
		SENDERR(EINVAL);
	}

	if(extr == NULL || extr->ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "error, extr or extr->ips pointer NULL\n");
		SENDERR(EINVAL);
	}

	sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);

	spin_lock_bh(&tdb_lock);

	ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said));
	if (ipsq == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "reserved ipsec_sa for SA: %s not found.  Call SADB_GETSPI first or call SADB_ADD instead.\n",
			    sa_len ? sa : " (error)");
		SENDERR(ENOENT);
	}

	if(ip_chk_addr((unsigned long)extr->ips->ips_said.dst.s_addr) == IS_MYADDR) {
		extr->ips->ips_flags |= EMT_INBOUND;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse: "
		    "existing ipsec_sa found (this is good) for SA: %s, %s-bound, updating.\n",
		    sa_len ? sa : " (error)",
		    extr->ips->ips_flags & EMT_INBOUND ? "in" : "out");

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (extr->ips->ips_natt_sport || extr->ips->ips_natt_dport) {
		KLIPS_PRINT(debug_pfkey,
			"klips_debug:pfkey_update_parse: only updating NAT-T ports "
			"(%u:%u -> %u:%u)\n", 
			ipsq->ips_natt_sport, ipsq->ips_natt_dport,
			extr->ips->ips_natt_sport, extr->ips->ips_natt_dport);

		if (extr->ips->ips_natt_sport) {
			ipsq->ips_natt_sport = extr->ips->ips_natt_sport;
			if (ipsq->ips_addr_s->sa_family == AF_INET) {
				((struct sockaddr_in *)(ipsq->ips_addr_s))->sin_port = htons(extr->ips->ips_natt_sport);
			}
		}

		if (extr->ips->ips_natt_dport) {
			ipsq->ips_natt_dport = extr->ips->ips_natt_dport;
			if (ipsq->ips_addr_d->sa_family == AF_INET) {
				((struct sockaddr_in *)(ipsq->ips_addr_d))->sin_port = htons(extr->ips->ips_natt_dport);
			}
		}

		nat_t_ips_saved = extr->ips;
		extr->ips = ipsq;
	}
	else {
#endif
	
	/* XXX extr->ips->ips_rcvif = &(enc_softc[em->em_if].enc_if);*/
	extr->ips->ips_rcvif = NULL;
	if ((error = pfkey_ipsec_sa_init(extr->ips, extensions))) {
		ipsec_sa_put(ipsq);
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "not successful for SA: %s, deleting.\n",
			    sa_len ? sa : " (error)");
		SENDERR(-error);
	}

	extr->ips->ips_life.ipl_addtime.ipl_count = ipsq->ips_life.ipl_addtime.ipl_count;
	ipsec_sa_put(ipsq);
	if((error = ipsec_sa_delchain(ipsq))) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "error=%d, trouble deleting intermediate ipsec_sa for SA=%s.\n",
			    error,
			    sa_len ? sa : " (error)");
		SENDERR(-error);
	}
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	}
#endif

	spin_unlock_bh(&tdb_lock);
	
	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_UPDATE,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							extr->ips->ips_replaywin,
							extr->ips->ips_state,
							extr->ips->ips_authalg,
							extr->ips->ips_encalg,
							extr->ips->ips_flags,
							extr->ips->ips_ref),
				 extensions_reply)
	     /* The 3 lifetime extentions should only be sent if non-zero. */
	     && (extensions[SADB_EXT_LIFETIME_HARD]
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_HARD],
								 SADB_EXT_LIFETIME_HARD,
								 extr->ips->ips_life.ipl_allocations.ipl_hard,
								 extr->ips->ips_life.ipl_bytes.ipl_hard,
								 extr->ips->ips_life.ipl_addtime.ipl_hard,
								 extr->ips->ips_life.ipl_usetime.ipl_hard,
								 extr->ips->ips_life.ipl_packets.ipl_hard),
				    extensions_reply) : 1)
	     && (extensions[SADB_EXT_LIFETIME_SOFT]
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_SOFT],
								 SADB_EXT_LIFETIME_SOFT,
								 extr->ips->ips_life.ipl_allocations.ipl_count,
								 extr->ips->ips_life.ipl_bytes.ipl_count,
								 extr->ips->ips_life.ipl_addtime.ipl_count,
								 extr->ips->ips_life.ipl_usetime.ipl_count,
								 extr->ips->ips_life.ipl_packets.ipl_count),
				    extensions_reply) : 1)
	     && (extr->ips->ips_life.ipl_allocations.ipl_count
		 || extr->ips->ips_life.ipl_bytes.ipl_count
		 || extr->ips->ips_life.ipl_addtime.ipl_count
		 || extr->ips->ips_life.ipl_usetime.ipl_count
		 || extr->ips->ips_life.ipl_packets.ipl_count

		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_CURRENT],
								 SADB_EXT_LIFETIME_CURRENT,
								 extr->ips->ips_life.ipl_allocations.ipl_count,
								 extr->ips->ips_life.ipl_bytes.ipl_count,
								 extr->ips->ips_life.ipl_addtime.ipl_count,
								 extr->ips->ips_life.ipl_usetime.ipl_count,
								 extr->ips->ips_life.ipl_packets.ipl_count),
				    extensions_reply) : 1)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_SRC],
							     SADB_EXT_ADDRESS_SRC,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_s),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
							     SADB_EXT_ADDRESS_DST,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_d),
				 extensions_reply)
	     && (extr->ips->ips_ident_s.data
                 ? pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[SADB_EXT_IDENTITY_SRC],
                                                              SADB_EXT_IDENTITY_SRC,
							      extr->ips->ips_ident_s.type,
							      extr->ips->ips_ident_s.id,
                                                              extr->ips->ips_ident_s.len,
							      extr->ips->ips_ident_s.data),
                                    extensions_reply) : 1)
	     && (extr->ips->ips_ident_d.data
                 ? pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[SADB_EXT_IDENTITY_DST],
                                                              SADB_EXT_IDENTITY_DST,
							      extr->ips->ips_ident_d.type,
							      extr->ips->ips_ident_d.id,
                                                              extr->ips->ips_ident_d.len,
							      extr->ips->ips_ident_d.data),
                                    extensions_reply) : 1)
#if 0
	     /* FIXME: This won't work yet because I have not finished
		it. */
	     && (extr->ips->ips_sens_
		 ? pfkey_safe_build(error = pfkey_sens_build(&extensions_reply[SADB_EXT_SENSITIVITY],
							     extr->ips->ips_sens_dpd,
							     extr->ips->ips_sens_sens_level,
							     extr->ips->ips_sens_sens_len,
							     extr->ips->ips_sens_sens_bitmap,
							     extr->ips->ips_sens_integ_level,
							     extr->ips->ips_sens_integ_len,
							     extr->ips->ips_sens_integ_bitmap),
				    extensions_reply) : 1)
#endif
		)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "failed to build the update reply message extensions\n");
		SENDERR(-error);
	}
		
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "failed to build the update reply message\n");
		SENDERR(-error);
	}
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
				    "sending up update reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "sending up update reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (nat_t_ips_saved) {
		/**
		 * As we _really_ update existing SA, we keep tdbq and need to delete
		 * parsed ips (nat_t_ips_saved, was extr->ips).
		 *
		 * goto errlab with extr->ips = nat_t_ips_saved will free it.
		 */

		extr->ips = nat_t_ips_saved;

		error = 0;
		KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse (NAT-T ports): "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");

		goto errlab;
	}
#endif

	if((error = ipsec_sa_add(extr->ips))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "failed to update the mature SA=%s with error=%d.\n",
			    sa_len ? sa : " (error)",
			    error);
		SENDERR(-error);
	}
	extr->ips = NULL;
	
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse: "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");
	
 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_add_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	struct ipsec_sa* ipsq;
	char sa[SATOA_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_add_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if(((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_state != SADB_SASTATE_MATURE) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "error, sa_state=%d must be MATURE=%d\n",
			    ((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_state,
			    SADB_SASTATE_MATURE);
		SENDERR(EINVAL);
	}

	if(!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "extr or extr->ips pointer NULL\n");
		SENDERR(EINVAL);
	}

	sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);

	ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said));
	if(ipsq != NULL) {
		ipsec_sa_put(ipsq);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "found an old ipsec_sa for SA%s, delete it first.\n",
			    sa_len ? sa : " (error)");
		SENDERR(EEXIST);
	}

	if(ip_chk_addr((unsigned long)extr->ips->ips_said.dst.s_addr) == IS_MYADDR) {
		extr->ips->ips_flags |= EMT_INBOUND;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_add_parse: "
		    "existing ipsec_sa not found (this is good) for SA%s, %s-bound, allocating.\n",
		    sa_len ? sa : " (error)",
		    extr->ips->ips_flags & EMT_INBOUND ? "in" : "out");
	
	/* XXX extr->ips->ips_rcvif = &(enc_softc[em->em_if].enc_if);*/
	extr->ips->ips_rcvif = NULL;
	
	if ((error = pfkey_ipsec_sa_init(extr->ips, extensions))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "not successful for SA: %s, deleting.\n",
			    sa_len ? sa : " (error)");
		SENDERR(-error);
	}

	extr->ips->ips_life.ipl_addtime.ipl_count = jiffies / HZ;
	if(!extr->ips->ips_life.ipl_allocations.ipl_count) {
		extr->ips->ips_life.ipl_allocations.ipl_count += 1;
	}

	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_ADD,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							extr->ips->ips_replaywin,
							extr->ips->ips_state,
							extr->ips->ips_authalg,
							extr->ips->ips_encalg,
							extr->ips->ips_flags,
							extr->ips->ips_ref),
				 extensions_reply)
	     /* The 3 lifetime extentions should only be sent if non-zero. */
	     && (extensions[SADB_EXT_LIFETIME_HARD]
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_HARD],
								 SADB_EXT_LIFETIME_HARD,
								 extr->ips->ips_life.ipl_allocations.ipl_hard,
								 extr->ips->ips_life.ipl_bytes.ipl_hard,
								 extr->ips->ips_life.ipl_addtime.ipl_hard,
								 extr->ips->ips_life.ipl_usetime.ipl_hard,
								 extr->ips->ips_life.ipl_packets.ipl_hard),
				    extensions_reply) : 1)
	     && (extensions[SADB_EXT_LIFETIME_SOFT]
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_SOFT],
								 SADB_EXT_LIFETIME_SOFT,
								 extr->ips->ips_life.ipl_allocations.ipl_soft,
								 extr->ips->ips_life.ipl_bytes.ipl_soft,
								 extr->ips->ips_life.ipl_addtime.ipl_soft,
								 extr->ips->ips_life.ipl_usetime.ipl_soft,
								 extr->ips->ips_life.ipl_packets.ipl_soft),
				    extensions_reply) : 1)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_SRC],
							     SADB_EXT_ADDRESS_SRC,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_s),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
							     SADB_EXT_ADDRESS_DST,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_d),
				 extensions_reply)
            && (extr->ips->ips_ident_s.data
                 ? pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[SADB_EXT_IDENTITY_SRC],
                                                              SADB_EXT_IDENTITY_SRC,
							      extr->ips->ips_ident_s.type,
							      extr->ips->ips_ident_s.id,
                                                              extr->ips->ips_ident_s.len,
							      extr->ips->ips_ident_s.data),
                                    extensions_reply) : 1)
            && (extr->ips->ips_ident_d.data
                 ? pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[SADB_EXT_IDENTITY_DST],
                                                              SADB_EXT_IDENTITY_DST,
							      extr->ips->ips_ident_d.type,
							      extr->ips->ips_ident_d.id,
                                                              extr->ips->ips_ident_d.len,
							      extr->ips->ips_ident_d.data),
                                    extensions_reply) : 1)
#if 0
	     /* FIXME: This won't work yet because I have not finished
		it. */
	     && (extr->ips->ips_sens_
		 ? pfkey_safe_build(error = pfkey_sens_build(&extensions_reply[SADB_EXT_SENSITIVITY],
							     extr->ips->ips_sens_dpd,
							     extr->ips->ips_sens_sens_level,
							     extr->ips->ips_sens_sens_len,
							     extr->ips->ips_sens_sens_bitmap,
							     extr->ips->ips_sens_integ_level,
							     extr->ips->ips_sens_integ_len,
							     extr->ips->ips_sens_integ_bitmap),
				    extensions_reply) : 1)
#endif
		)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "failed to build the add reply message extensions\n");
		SENDERR(-error);
	}
		
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "failed to build the add reply message\n");
		SENDERR(-error);
	}
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
				    "sending up add reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "sending up add reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

	if((error = ipsec_sa_add(extr->ips))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "failed to add the mature SA=%s with error=%d.\n",
			    sa_len ? sa : " (error)",
			    error);
		SENDERR(-error);
	}
	extr->ips = NULL;
	
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_add_parse: "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");
	
 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_delete_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	struct ipsec_sa *ipsp;
	char sa[SATOA_BUF];
	size_t sa_len;
	int error = 0;
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_delete_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if(!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_delete_parse: "
			    "extr or extr->ips pointer NULL, fatal\n");
		SENDERR(EINVAL);
	}

	sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);

	spin_lock_bh(&tdb_lock);

	ipsp = ipsec_sa_getbyid(&(extr->ips->ips_said));
	if (ipsp == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_delete_parse: "
			    "ipsec_sa not found for SA:%s, could not delete.\n",
			    sa_len ? sa : " (error)");
		SENDERR(ESRCH);
	}

	ipsec_sa_put(ipsp);
	if((error = ipsec_sa_delchain(ipsp))) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_delete_parse: "
			    "error=%d returned trying to delete ipsec_sa for SA:%s.\n",
			    error,
			    sa_len ? sa : " (error)");
		SENDERR(-error);
	}
	spin_unlock_bh(&tdb_lock);

	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_DELETE,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							0,
							0,
							0,
							0,
							0,
							extr->ips->ips_ref),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_SRC],
							     SADB_EXT_ADDRESS_SRC,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_s),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
							     SADB_EXT_ADDRESS_DST,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_d),
				 extensions_reply)
		)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
			    "failed to build the delete reply message extensions\n");
		SENDERR(-error);
	}
	
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
			    "failed to build the delete reply message\n");
		SENDERR(-error);
	}
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
				    "sending up delete reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
			    "sending up delete reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_get_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	struct ipsec_sa *ipsp;
	char sa[SATOA_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_get_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if(!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_get_parse: "
			    "extr or extr->ips pointer NULL, fatal\n");
		SENDERR(EINVAL);
	}

	sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);

	spin_lock_bh(&tdb_lock);

	ipsp = ipsec_sa_getbyid(&(extr->ips->ips_said));
	if (ipsp == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "ipsec_sa not found for SA=%s, could not get.\n",
			    sa_len ? sa : " (error)");
		SENDERR(ESRCH);
	}
	
	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_GET,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							extr->ips->ips_replaywin,
							extr->ips->ips_state,
							extr->ips->ips_authalg,
							extr->ips->ips_encalg,
							extr->ips->ips_flags,
							extr->ips->ips_ref),
				 extensions_reply)
	     /* The 3 lifetime extentions should only be sent if non-zero. */
	     && (ipsp->ips_life.ipl_allocations.ipl_count
		 || ipsp->ips_life.ipl_bytes.ipl_count
		 || ipsp->ips_life.ipl_addtime.ipl_count
		 || ipsp->ips_life.ipl_usetime.ipl_count
		 || ipsp->ips_life.ipl_packets.ipl_count
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_CURRENT],
								 SADB_EXT_LIFETIME_CURRENT,
								 ipsp->ips_life.ipl_allocations.ipl_count,
								 ipsp->ips_life.ipl_bytes.ipl_count,
								 ipsp->ips_life.ipl_addtime.ipl_count,
								 ipsp->ips_life.ipl_usetime.ipl_count,
								 ipsp->ips_life.ipl_packets.ipl_count),
				    extensions_reply) : 1)
	     && (ipsp->ips_life.ipl_allocations.ipl_hard
		 || ipsp->ips_life.ipl_bytes.ipl_hard
		 || ipsp->ips_life.ipl_addtime.ipl_hard
		 || ipsp->ips_life.ipl_usetime.ipl_hard
		 || ipsp->ips_life.ipl_packets.ipl_hard
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_HARD],
								 SADB_EXT_LIFETIME_HARD,
								 ipsp->ips_life.ipl_allocations.ipl_hard,
								 ipsp->ips_life.ipl_bytes.ipl_hard,
								 ipsp->ips_life.ipl_addtime.ipl_hard,
								 ipsp->ips_life.ipl_usetime.ipl_hard,
								 ipsp->ips_life.ipl_packets.ipl_hard),
				    extensions_reply) : 1)
	     && (ipsp->ips_life.ipl_allocations.ipl_soft
		 || ipsp->ips_life.ipl_bytes.ipl_soft
		 || ipsp->ips_life.ipl_addtime.ipl_soft
		 || ipsp->ips_life.ipl_usetime.ipl_soft
		 || ipsp->ips_life.ipl_packets.ipl_soft
		 ? pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[SADB_EXT_LIFETIME_SOFT],
								 SADB_EXT_LIFETIME_SOFT,
								 ipsp->ips_life.ipl_allocations.ipl_soft,
								 ipsp->ips_life.ipl_bytes.ipl_soft,
								 ipsp->ips_life.ipl_addtime.ipl_soft,
								 ipsp->ips_life.ipl_usetime.ipl_soft,
								 ipsp->ips_life.ipl_packets.ipl_soft),
				    extensions_reply) : 1)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_SRC],
							     SADB_EXT_ADDRESS_SRC,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_s),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
							     SADB_EXT_ADDRESS_DST,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_d),
				 extensions_reply)
	     && (extr->ips->ips_addr_p
		 ? pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_PROXY],
								SADB_EXT_ADDRESS_PROXY,
								0, /*extr->ips->ips_said.proto,*/
								0,
								extr->ips->ips_addr_p),
				    extensions_reply) : 1)
#if 0
	     /* FIXME: This won't work yet because the keys are not
		stored directly in the ipsec_sa.  They are stored as
		contexts. */
	     && (extr->ips->ips_key_a_size
		 ? pfkey_safe_build(error = pfkey_key_build(&extensions_reply[SADB_EXT_KEY_AUTH],
							    SADB_EXT_KEY_AUTH,
							    extr->ips->ips_key_a_size * 8,
							    extr->ips->ips_key_a),
				    extensions_reply) : 1)
	     /* FIXME: This won't work yet because the keys are not
		stored directly in the ipsec_sa.  They are stored as
		key schedules. */
	     && (extr->ips->ips_key_e_size
		 ? pfkey_safe_build(error = pfkey_key_build(&extensions_reply[SADB_EXT_KEY_ENCRYPT],
							    SADB_EXT_KEY_ENCRYPT,
							    extr->ips->ips_key_e_size * 8,
							    extr->ips->ips_key_e),
				    extensions_reply) : 1)
#endif
	     && (extr->ips->ips_ident_s.data
                 ? pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[SADB_EXT_IDENTITY_SRC],
                                                              SADB_EXT_IDENTITY_SRC,
							      extr->ips->ips_ident_s.type,
							      extr->ips->ips_ident_s.id,
                                                              extr->ips->ips_ident_s.len,
							      extr->ips->ips_ident_s.data),
                                    extensions_reply) : 1)
	     && (extr->ips->ips_ident_d.data
                 ? pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[SADB_EXT_IDENTITY_DST],
                                                              SADB_EXT_IDENTITY_DST,
							      extr->ips->ips_ident_d.type,
							      extr->ips->ips_ident_d.id,
                                                              extr->ips->ips_ident_d.len,
							      extr->ips->ips_ident_d.data),
                                    extensions_reply) : 1)
#if 0
	     /* FIXME: This won't work yet because I have not finished
		it. */
	     && (extr->ips->ips_sens_
		 ? pfkey_safe_build(error = pfkey_sens_build(&extensions_reply[SADB_EXT_SENSITIVITY],
							     extr->ips->ips_sens_dpd,
							     extr->ips->ips_sens_sens_level,
							     extr->ips->ips_sens_sens_len,
							     extr->ips->ips_sens_sens_bitmap,
							     extr->ips->ips_sens_integ_level,
							     extr->ips->ips_sens_integ_len,
							     extr->ips->ips_sens_integ_bitmap),
				    extensions_reply) : 1)
#endif
		     )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "failed to build the get reply message extensions\n");
		ipsec_sa_put(ipsp);
		spin_unlock_bh(&tdb_lock);
		SENDERR(-error);
	}
		
	ipsec_sa_put(ipsp);
	spin_unlock_bh(&tdb_lock);
	
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "failed to build the get reply message\n");
		SENDERR(-error);
	}
	
	if((error = pfkey_upmsg(sk->socket, pfkey_reply))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "failed to send the get reply message\n");
		SENDERR(-error);
	}
	
	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
		    "succeeded in sending get reply message.\n");
	
 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_acquire_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_acquire_parse: .\n");

	/* XXX I don't know if we want an upper bound, since userspace may
	   want to register itself for an satype > SADB_SATYPE_MAX. */
	if((satype == 0) || (satype > SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_acquire_parse: "
			    "SATYPE=%d invalid.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if(!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire_parse: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}

	for(pfkey_socketsp = pfkey_registered_sockets[satype];
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp,
					((struct sadb_msg*)extensions[SADB_EXT_RESERVED])))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire_parse: "
				    "sending up acquire reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire_parse: "
			    "sending up acquire reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_register_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_register_parse: .\n");

	/* XXX I don't know if we want an upper bound, since userspace may
	   want to register itself for an satype > SADB_SATYPE_MAX. */
	if((satype == 0) || (satype > SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_parse: "
			    "SATYPE=%d invalid.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if(!pfkey_list_insert_socket(sk->socket,
				 &(pfkey_registered_sockets[satype]))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_parse: "
			    "SATYPE=%02d(%s) successfully registered by KMd (pid=%d).\n",
			    satype,
			    satype2name(satype),
			    key_pid(sk));
	};
	
	/* send up register msg with supported SATYPE algos */

	error=pfkey_register_reply(satype, (struct sadb_msg*)extensions[SADB_EXT_RESERVED]);
 errlab:
	return error;
}
int
pfkey_register_reply(int satype, struct sadb_msg *sadb_msg)
{
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	struct supported_list *pfkey_supported_listp;
	unsigned int alg_num_a = 0, alg_num_e = 0;
	struct sadb_alg *alg_a = NULL, *alg_e = NULL, *alg_ap = NULL, *alg_ep = NULL;
	int error = 0;

	pfkey_extensions_init(extensions_reply);

	if((satype == 0) || (satype > SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "SAtype=%d unspecified or unknown.\n",
			    satype);
		SENDERR(EINVAL);
	}
	if(!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}
	/* send up register msg with supported SATYPE algos */
	pfkey_supported_listp = pfkey_supported_list[satype];
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_register_reply: "
		    "pfkey_supported_list[%d]=0p%p\n",
		    satype,
		    pfkey_supported_list[satype]);
	while(pfkey_supported_listp) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_reply: "
			    "checking supported=0p%p\n",
			    pfkey_supported_listp);
		if(pfkey_supported_listp->supportedp->supported_alg_exttype == SADB_EXT_SUPPORTED_AUTH) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "adding auth alg.\n");
			alg_num_a++;
		}
		if(pfkey_supported_listp->supportedp->supported_alg_exttype == SADB_EXT_SUPPORTED_ENCRYPT) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "adding encrypt alg.\n");
			alg_num_e++;
		}
		pfkey_supported_listp = pfkey_supported_listp->next;
	}
	
	if(alg_num_a) {
		KLIPS_PRINT(debug_pfkey,
		            "klips_debug:pfkey_register_reply: "
		            "allocating %lu bytes for auth algs.\n",
		            (unsigned long) (alg_num_a * sizeof(struct sadb_alg)));
		if((alg_a = kmalloc(alg_num_a * sizeof(struct sadb_alg), GFP_ATOMIC) ) == NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "auth alg memory allocation error\n");
			SENDERR(ENOMEM);
		}
		alg_ap = alg_a;
	}
	
	if(alg_num_e) {
		KLIPS_PRINT(debug_pfkey,
		            "klips_debug:pfkey_register_reply: "
		            "allocating %lu bytes for enc algs.\n",
		            (unsigned long) (alg_num_e * sizeof(struct sadb_alg)));
		if((alg_e = kmalloc(alg_num_e * sizeof(struct sadb_alg), GFP_ATOMIC) ) == NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "enc alg memory allocation error\n");
			SENDERR(ENOMEM);
		}
		alg_ep = alg_e;
	}
	
	pfkey_supported_listp = pfkey_supported_list[satype];
	while(pfkey_supported_listp) {
		if(alg_num_a) {
			if(pfkey_supported_listp->supportedp->supported_alg_exttype == SADB_EXT_SUPPORTED_AUTH) {
				alg_ap->sadb_alg_id = pfkey_supported_listp->supportedp->supported_alg_id;
				alg_ap->sadb_alg_ivlen = pfkey_supported_listp->supportedp->supported_alg_ivlen;
				alg_ap->sadb_alg_minbits = pfkey_supported_listp->supportedp->supported_alg_minbits;
				alg_ap->sadb_alg_maxbits = pfkey_supported_listp->supportedp->supported_alg_maxbits;
				alg_ap->sadb_alg_reserved = 0;
				KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
					    "klips_debug:pfkey_register_reply: "
					    "adding auth=0p%p\n",
					    alg_ap);
				alg_ap++;
			}
		}
		if(alg_num_e) {
			if(pfkey_supported_listp->supportedp->supported_alg_exttype == SADB_EXT_SUPPORTED_ENCRYPT) {
				alg_ep->sadb_alg_id = pfkey_supported_listp->supportedp->supported_alg_id;
				alg_ep->sadb_alg_ivlen = pfkey_supported_listp->supportedp->supported_alg_ivlen;
				alg_ep->sadb_alg_minbits = pfkey_supported_listp->supportedp->supported_alg_minbits;
				alg_ep->sadb_alg_maxbits = pfkey_supported_listp->supportedp->supported_alg_maxbits;
				alg_ep->sadb_alg_reserved = 0;
				KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
					    "klips_debug:pfkey_register_reply: "
					    "adding encrypt=0p%p\n",
					    alg_ep);
				alg_ep++;
			}
		}
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_reply: "
			    "found satype=%d(%s) exttype=%d id=%d ivlen=%d minbits=%d maxbits=%d.\n",
			    satype,
			    satype2name(satype),
			    pfkey_supported_listp->supportedp->supported_alg_exttype,
			    pfkey_supported_listp->supportedp->supported_alg_id,
			    pfkey_supported_listp->supportedp->supported_alg_ivlen,
			    pfkey_supported_listp->supportedp->supported_alg_minbits,
			    pfkey_supported_listp->supportedp->supported_alg_maxbits);
		pfkey_supported_listp = pfkey_supported_listp->next;
	}
	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_REGISTER,
							  satype,
							  0,
							  sadb_msg? sadb_msg->sadb_msg_seq : ++pfkey_msg_seq,
							  sadb_msg? sadb_msg->sadb_msg_pid: current->pid),
			      extensions_reply) &&
	     (alg_num_a ? pfkey_safe_build(error = pfkey_supported_build(&extensions_reply[SADB_EXT_SUPPORTED_AUTH],
									SADB_EXT_SUPPORTED_AUTH,
									alg_num_a,
									alg_a),
					  extensions_reply) : 1) &&
	     (alg_num_e ? pfkey_safe_build(error = pfkey_supported_build(&extensions_reply[SADB_EXT_SUPPORTED_ENCRYPT],
									SADB_EXT_SUPPORTED_ENCRYPT,
									alg_num_e,
									alg_e),
					  extensions_reply) : 1))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "failed to build the register message extensions_reply\n");
		SENDERR(-error);
	}
	
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "failed to build the register message\n");
		SENDERR(-error);
	}
	/* this should go to all registered sockets for that satype only */
	for(pfkey_socketsp = pfkey_registered_sockets[satype];
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
				    "sending up acquire message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "sending up register message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
 errlab:
	if(alg_a) {
		kfree(alg_a);
	}
	if(alg_e) {
		kfree(alg_e);
	}
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_expire_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	struct socket_list *pfkey_socketsp;
#ifdef CONFIG_IPSEC_DEBUG
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;
#endif /* CONFIG_IPSEC_DEBUG */

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_expire_parse: .\n");

	if(pfkey_open_sockets) {
		for(pfkey_socketsp = pfkey_open_sockets;
		    pfkey_socketsp;
		    pfkey_socketsp = pfkey_socketsp->next) {
			if((error = pfkey_upmsg(pfkey_socketsp->socketp,
						((struct sadb_msg*)extensions[SADB_EXT_RESERVED])))) {
				KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire_parse: "
					    "sending up expire reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
					    satype,
					    satype2name(satype),
					    pfkey_socketsp->socketp,
					    error);
				SENDERR(-error);
			}
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire_parse: "
				    "sending up expire reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp);
		}
	}

 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_flush_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;
	uint8_t proto = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_flush_parse: "
		    "flushing type %d SAs\n",
		    satype);

	if(satype && !(proto = satype2proto(satype))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_flush_parse: "
			    "satype %d lookup failed.\n", 
			    ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype);
		SENDERR(EINVAL);
	}

	if ((error = ipsec_sadb_cleanup(proto))) {
		SENDERR(-error);
	}

	if(pfkey_open_sockets) {
		for(pfkey_socketsp = pfkey_open_sockets;
		    pfkey_socketsp;
		    pfkey_socketsp = pfkey_socketsp->next) {
			if((error = pfkey_upmsg(pfkey_socketsp->socketp,
						((struct sadb_msg*)extensions[SADB_EXT_RESERVED])))) {
				KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_flush_parse: "
					    "sending up flush reply message for satype=%d(%s) (proto=%d) to socket=0p%p failed with error=%d.\n",
					    satype,
					    satype2name(satype),
					    proto,
					    pfkey_socketsp->socketp,
					    error);
				SENDERR(-error);
			}
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_flush_parse: "
				    "sending up flush reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp);
		}
	}

 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_dump_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_dump_parse: .\n");

	SENDERR(ENOSYS);
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_promisc_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_promisc_parse: .\n");

	SENDERR(ENOSYS);
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_pchange_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_pchange_parse: .\n");

	SENDERR(ENOSYS);
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_grpsa_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	struct ipsec_sa *ips1p, *ips2p, *ipsp;
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;
	char sa1[SATOA_BUF], sa2[SATOA_BUF];
	size_t sa_len1, sa_len2 = 0;
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_grpsa_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if(extr == NULL || extr->ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "extr or extr->ips is NULL, fatal.\n");
		SENDERR(EINVAL);
	}

	sa_len1 = satoa(extr->ips->ips_said, 0, sa1, SATOA_BUF);
	if(extr->ips2 != NULL) {
		sa_len2 = satoa(extr->ips2->ips_said, 0, sa2, SATOA_BUF);
	}

	spin_lock_bh(&tdb_lock);

	ips1p = ipsec_sa_getbyid(&(extr->ips->ips_said));
	if(ips1p == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "reserved ipsec_sa for SA1: %s not found.  Call SADB_ADD/UPDATE first.\n",
			    sa_len1 ? sa1 : " (error)");
		SENDERR(ENOENT);
	}
	if(extr->ips2) { /* GRPSA */
		ips2p = ipsec_sa_getbyid(&(extr->ips2->ips_said));
		if(ips2p == NULL) {
			ipsec_sa_put(ips1p);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_grpsa_parse: "
				    "reserved ipsec_sa for SA2: %s not found.  Call SADB_ADD/UPDATE first.\n",
				    sa_len2 ? sa2 : " (error)");
			SENDERR(ENOENT);
		}

		/* Is either one already linked? */
		if(ips1p->ips_onext) {
			ipsec_sa_put(ips1p);
			ipsec_sa_put(ips2p);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_grpsa_parse: "
				    "ipsec_sa for SA: %s is already linked.\n",
				    sa_len1 ? sa1 : " (error)");
			SENDERR(EEXIST);
		}
		if(ips2p->ips_inext) {
			ipsec_sa_put(ips1p);
			ipsec_sa_put(ips2p);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_grpsa_parse: "
				    "ipsec_sa for SA: %s is already linked.\n",
				    sa_len2 ? sa2 : " (error)");
			SENDERR(EEXIST);
		}
		
		/* Is extr->ips already linked to extr->ips2? */
		ipsp = ips2p;
		while(ipsp) {
			if(ipsp == ips1p) {
				ipsec_sa_put(ips1p);
				ipsec_sa_put(ips2p);
				spin_unlock_bh(&tdb_lock);
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_x_grpsa_parse: "
					    "ipsec_sa for SA: %s is already linked to %s.\n",
					    sa_len1 ? sa1 : " (error)",
					    sa_len2 ? sa2 : " (error)");
				SENDERR(EEXIST);
			}
			ipsp = ipsp->ips_onext;
		}
		
		/* link 'em */
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "linking ipsec_sa SA: %s with %s.\n",
			    sa_len1 ? sa1 : " (error)",
			    sa_len2 ? sa2 : " (error)");
		ips1p->ips_onext = ips2p;
		ips2p->ips_inext = ips1p;
	} else { /* UNGRPSA */
		ipsec_sa_put(ips1p);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "unlinking ipsec_sa SA: %s.\n",
			    sa_len1 ? sa1 : " (error)");
		while(ips1p->ips_onext) {
			ips1p = ips1p->ips_onext;
		}
		while(ips1p->ips_inext) {
			ipsp = ips1p;
			ips1p = ips1p->ips_inext;
			ipsec_sa_put(ips1p);
			ipsp->ips_inext = NULL;
			ipsec_sa_put(ipsp);
			ips1p->ips_onext = NULL;
		}
	}

	spin_unlock_bh(&tdb_lock);

	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_X_GRPSA,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							extr->ips->ips_replaywin,
							extr->ips->ips_state,
							extr->ips->ips_authalg,
							extr->ips->ips_encalg,
							extr->ips->ips_flags,
							extr->ips->ips_ref),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
							     SADB_EXT_ADDRESS_DST,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips->ips_addr_d),
				 extensions_reply)
	     && (extr->ips2
		 ? (pfkey_safe_build(error = pfkey_x_satype_build(&extensions_reply[SADB_X_EXT_SATYPE2],
								  ((struct sadb_x_satype*)extensions[SADB_X_EXT_SATYPE2])->sadb_x_satype_satype
								  /* proto2satype(extr->ips2->ips_said.proto) */),
								  extensions_reply)
				     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_X_EXT_SA2],
										SADB_X_EXT_SA2,
										extr->ips2->ips_said.spi,
										extr->ips2->ips_replaywin,
										extr->ips2->ips_state,
										extr->ips2->ips_authalg,
										extr->ips2->ips_encalg,
										extr->ips2->ips_flags,
										extr->ips2->ips_ref),
							 extensions_reply)
				     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_DST2],
										     SADB_X_EXT_ADDRESS_DST2,
										     0, /*extr->ips->ips_said.proto,*/
										     0,
										     extr->ips2->ips_addr_d),
							 extensions_reply) ) : 1 )
		     )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
			    "failed to build the x_grpsa reply message extensions\n");
		SENDERR(-error);
	}
	   
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
			    "failed to build the x_grpsa reply message\n");
		SENDERR(-error);
	}
	
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
				    "sending up x_grpsa reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
			    "sending up x_grpsa reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
		    "succeeded in sending x_grpsa reply message.\n");
	
 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_addflow_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
#ifdef CONFIG_IPSEC_DEBUG
	char buf1[64], buf2[64];
#endif /* CONFIG_IPSEC_DEBUG */
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;
	ip_address srcflow, dstflow, srcmask, dstmask;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_addflow_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	memset((caddr_t)&srcflow, 0, sizeof(srcflow));
	memset((caddr_t)&dstflow, 0, sizeof(dstflow));
	memset((caddr_t)&srcmask, 0, sizeof(srcmask));
	memset((caddr_t)&dstmask, 0, sizeof(dstmask));

	if(!extr || !(extr->ips) || !(extr->eroute)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "missing extr, ipsec_sa or eroute data.\n");
		SENDERR(EINVAL);
	}

	srcflow.u.v4.sin_family = AF_INET;
	dstflow.u.v4.sin_family = AF_INET;
	srcmask.u.v4.sin_family = AF_INET;
	dstmask.u.v4.sin_family = AF_INET;
	srcflow.u.v4.sin_addr = extr->eroute->er_eaddr.sen_ip_src;
	dstflow.u.v4.sin_addr = extr->eroute->er_eaddr.sen_ip_dst;
	srcmask.u.v4.sin_addr = extr->eroute->er_emask.sen_ip_src;
	dstmask.u.v4.sin_addr = extr->eroute->er_emask.sen_ip_dst;

#ifdef CONFIG_IPSEC_DEBUG
	if (debug_pfkey) {
		subnettoa(extr->eroute->er_eaddr.sen_ip_src,
			  extr->eroute->er_emask.sen_ip_src, 0, buf1, sizeof(buf1));
		subnettoa(extr->eroute->er_eaddr.sen_ip_dst,
			  extr->eroute->er_emask.sen_ip_dst, 0, buf2, sizeof(buf2));
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "calling breakeroute and/or makeroute for %s->%s\n",
			    buf1, buf2);
	}
#endif /* CONFIG_IPSEC_DEBUG */
	if(extr->ips->ips_flags & SADB_X_SAFLAGS_INFLOW) {
/*	if(ip_chk_addr((unsigned long)extr->ips->ips_said.dst.s_addr) == IS_MYADDR) */ 
		struct ipsec_sa *ipsp, *ipsq;
		char sa[SATOA_BUF];
		size_t sa_len;

		ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said));
		if(ipsq == NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "ipsec_sa not found, cannot set incoming policy.\n");
			SENDERR(ENOENT);
		}

		ipsp = ipsq;
		while(ipsp && ipsp->ips_said.proto != IPPROTO_IPIP) {
			ipsp = ipsp->ips_inext;
		}

		if(ipsp == NULL) {
			ipsec_sa_put(ipsq);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "SA chain does not have an IPIP SA, cannot set incoming policy.\n");
			SENDERR(ENOENT);
		}

		sa_len = satoa(extr->ips->ips_said, 0, sa, SATOA_BUF);

		ipsp->ips_flags |= SADB_X_SAFLAGS_INFLOW;
		ipsp->ips_flow_s = srcflow;
		ipsp->ips_flow_d = dstflow;
		ipsp->ips_mask_s = srcmask;
		ipsp->ips_mask_d = dstmask;

		ipsec_sa_put(ipsq);

		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "inbound eroute, setting incoming policy information in IPIP ipsec_sa for SA: %s.\n",
			    sa_len ? sa : " (error)");
	} else {
		struct sk_buff *first = NULL, *last = NULL;

		if(extr->ips->ips_flags & SADB_X_SAFLAGS_REPLACEFLOW) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "REPLACEFLOW flag set, calling breakeroute.\n");
			if ((error = ipsec_breakroute(&(extr->eroute->er_eaddr),
						      &(extr->eroute->er_emask),
						      &first, &last))) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_x_addflow_parse: "
					    "breakeroute returned %d.  first=0p%p, last=0p%p\n",
					    error,
					    first,
					    last);
				if(first != NULL) {
					ipsec_kfree_skb(first);
				}
				if(last != NULL) {
					ipsec_kfree_skb(last);
				}
				SENDERR(-error);
			}
		}
		
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "calling makeroute.\n");
		
		if ((error = ipsec_makeroute(&(extr->eroute->er_eaddr),
					     &(extr->eroute->er_emask),
					     extr->ips->ips_said,
					     ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid,
					     NULL,
					     &(extr->ips->ips_ident_s),
					     &(extr->ips->ips_ident_d)))) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "makeroute returned %d.\n", error);
			SENDERR(-error);
		}
		if(first != NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "first=0p%p HOLD packet re-injected.\n",
				    first);
			DEV_QUEUE_XMIT(first, first->dev, SOPRI_NORMAL);
		}
		if(last != NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "last=0p%p HOLD packet re-injected.\n",
				    last);
			DEV_QUEUE_XMIT(last, last->dev, SOPRI_NORMAL);
		}
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_addflow_parse: "
		    "makeroute call successful.\n");

	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_X_ADDFLOW,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							extr->ips->ips_replaywin,
							extr->ips->ips_state,
							extr->ips->ips_authalg,
							extr->ips->ips_encalg,
							extr->ips->ips_flags,
							extr->ips->ips_ref),
				 extensions_reply)
	     && (extensions[SADB_EXT_ADDRESS_SRC]
		 ? pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_SRC],
								SADB_EXT_ADDRESS_SRC,
								0, /*extr->ips->ips_said.proto,*/
								0,
								extr->ips->ips_addr_s),
				    extensions_reply) : 1)
	     && (extensions[SADB_EXT_ADDRESS_DST]
		 ? pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_EXT_ADDRESS_DST],
								SADB_EXT_ADDRESS_DST,
								0, /*extr->ips->ips_said.proto,*/
								0,
								extr->ips->ips_addr_d),
				    extensions_reply) : 1)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_SRC_FLOW],
							     SADB_X_EXT_ADDRESS_SRC_FLOW,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&srcflow),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_DST_FLOW],
							     SADB_X_EXT_ADDRESS_DST_FLOW,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&dstflow),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_SRC_MASK],
							     SADB_X_EXT_ADDRESS_SRC_MASK,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&srcmask),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_DST_MASK],
							     SADB_X_EXT_ADDRESS_DST_MASK,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&dstmask),
				 extensions_reply)
		)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
			    "failed to build the x_addflow reply message extensions\n");
		SENDERR(-error);
	}
		
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
			    "failed to build the x_addflow reply message\n");
		SENDERR(-error);
	}
	
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
				    "sending up x_addflow reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
			    "sending up x_addflow reply message for satype=%d(%s) (proto=%d) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    extr->ips->ips_said.proto,
			    pfkey_socketsp->socketp);
	}
	
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_addflow_parse: "
		    "extr->ips cleaned up and freed.\n");

 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_delflow_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;
#ifdef CONFIG_IPSEC_DEBUG
	char buf1[64], buf2[64];
#endif /* CONFIG_IPSEC_DEBUG */
	struct sadb_ext *extensions_reply[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype = ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype;
	ip_address srcflow, dstflow, srcmask, dstmask;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_delflow_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	memset((caddr_t)&srcflow, 0, sizeof(srcflow));
	memset((caddr_t)&dstflow, 0, sizeof(dstflow));
	memset((caddr_t)&srcmask, 0, sizeof(srcmask));
	memset((caddr_t)&dstmask, 0, sizeof(dstmask));

	if(!extr || !(extr->ips)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_delflow_parse: "
			    "extr, or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	if(extr->ips->ips_flags & SADB_X_SAFLAGS_CLEARFLOW) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_delflow_parse: "
			    "CLEARFLOW flag set, calling cleareroutes.\n");
		if ((error = ipsec_cleareroutes()))
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "cleareroutes returned %d.\n", error);
			SENDERR(-error);
	} else {
		struct sk_buff *first = NULL, *last = NULL;

		if(!(extr->eroute)) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "extr->eroute is NULL, fatal.\n");
			SENDERR(EINVAL);
		}
		
		srcflow.u.v4.sin_family = AF_INET;
		dstflow.u.v4.sin_family = AF_INET;
		srcmask.u.v4.sin_family = AF_INET;
		dstmask.u.v4.sin_family = AF_INET;
		srcflow.u.v4.sin_addr = extr->eroute->er_eaddr.sen_ip_src;
		dstflow.u.v4.sin_addr = extr->eroute->er_eaddr.sen_ip_dst;
		srcmask.u.v4.sin_addr = extr->eroute->er_emask.sen_ip_src;
		dstmask.u.v4.sin_addr = extr->eroute->er_emask.sen_ip_dst;

#ifdef CONFIG_IPSEC_DEBUG
		if (debug_pfkey) {
			subnettoa(extr->eroute->er_eaddr.sen_ip_src,
				  extr->eroute->er_emask.sen_ip_src, 0, buf1, sizeof(buf1));
			subnettoa(extr->eroute->er_eaddr.sen_ip_dst,
				  extr->eroute->er_emask.sen_ip_dst, 0, buf2, sizeof(buf2));
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "calling breakeroute for %s->%s\n",
				    buf1, buf2);
		}
#endif /* CONFIG_IPSEC_DEBUG */
		error = ipsec_breakroute(&(extr->eroute->er_eaddr),
					     &(extr->eroute->er_emask),
					     &first, &last);
		if(error) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "breakeroute returned %d.  first=0p%p, last=0p%p\n",
				    error,
				    first,
				    last);
		}
		if(first != NULL) {
			ipsec_kfree_skb(first);
		}
		if(last != NULL) {
			ipsec_kfree_skb(last);
		}
		if(error) {
			SENDERR(-error);
		}
	}
	
	if(!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							  SADB_X_DELFLOW,
							  satype,
							  0,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_seq,
							  ((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_pid),
			      extensions_reply)
	     && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions_reply[SADB_EXT_SA],
							SADB_EXT_SA,
							extr->ips->ips_said.spi,
							extr->ips->ips_replaywin,
							extr->ips->ips_state,
							extr->ips->ips_authalg,
							extr->ips->ips_encalg,
							extr->ips->ips_flags,
							extr->ips->ips_ref),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_SRC_FLOW],
							     SADB_X_EXT_ADDRESS_SRC_FLOW,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&srcflow),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_DST_FLOW],
							     SADB_X_EXT_ADDRESS_DST_FLOW,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&dstflow),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_SRC_MASK],
							     SADB_X_EXT_ADDRESS_SRC_MASK,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&srcmask),
				 extensions_reply)
	     && pfkey_safe_build(error = pfkey_address_build(&extensions_reply[SADB_X_EXT_ADDRESS_DST_MASK],
							     SADB_X_EXT_ADDRESS_DST_MASK,
							     0, /*extr->ips->ips_said.proto,*/
							     0,
							     (struct sockaddr*)&dstmask),
				 extensions_reply)
		)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
			    "failed to build the x_delflow reply message extensions\n");
		SENDERR(-error);
	}
		
	if((error = pfkey_msg_build(&pfkey_reply, extensions_reply, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
			    "failed to build the x_delflow reply message\n");
		SENDERR(-error);
	}
	
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
				    "sending up x_delflow reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
			    "sending up x_delflow reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_delflow_parse: "
		    "extr->ips cleaned up and freed.\n");

 errlab:
	if (pfkey_reply) {
		pfkey_msg_free(&pfkey_reply);
	}
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_msg_debug_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_msg_debug_parse: .\n");

/* errlab:*/
	return error;
}

/* pfkey_expire expects the ipsec_sa table to be locked before being called. */
int
pfkey_expire(struct ipsec_sa *ipsp, int hard)
{
	struct sadb_ext *extensions[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_msg = NULL;
	struct socket_list *pfkey_socketsp;
	int error = 0;
	uint8_t satype;

	pfkey_extensions_init(extensions);

	if(!(satype = proto2satype(ipsp->ips_said.proto))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_expire: "
			    "satype lookup for protocol %d lookup failed.\n", 
			    ipsp->ips_said.proto);
		SENDERR(EINVAL);
	}
	
	if(!pfkey_open_sockets) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "no sockets listening.\n");
		SENDERR(EPROTONOSUPPORT);
	}

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions[0],
							   SADB_EXPIRE,
							   satype,
							   0,
							   ++pfkey_msg_seq,
							   0),
			       extensions)
	      && pfkey_safe_build(error = pfkey_sa_ref_build(&extensions[SADB_EXT_SA],
							 SADB_EXT_SA,
							 ipsp->ips_said.spi,
							 ipsp->ips_replaywin,
							 ipsp->ips_state,
							 ipsp->ips_authalg,
							 ipsp->ips_encalg,
							 ipsp->ips_flags,
							 ipsp->ips_ref),
				  extensions)
	      && pfkey_safe_build(error = pfkey_lifetime_build(&extensions[SADB_EXT_LIFETIME_CURRENT],
							       SADB_EXT_LIFETIME_CURRENT,
							       ipsp->ips_life.ipl_allocations.ipl_count,
							       ipsp->ips_life.ipl_bytes.ipl_count,
							       ipsp->ips_life.ipl_addtime.ipl_count,
							       ipsp->ips_life.ipl_usetime.ipl_count,
							       ipsp->ips_life.ipl_packets.ipl_count),
				  extensions)
	      && (hard ? 
		  pfkey_safe_build(error = pfkey_lifetime_build(&extensions[SADB_EXT_LIFETIME_HARD],
								SADB_EXT_LIFETIME_HARD,
								ipsp->ips_life.ipl_allocations.ipl_hard,
								ipsp->ips_life.ipl_bytes.ipl_hard,
								ipsp->ips_life.ipl_addtime.ipl_hard,
								ipsp->ips_life.ipl_usetime.ipl_hard,
								ipsp->ips_life.ipl_packets.ipl_hard),
				   extensions)
		  : pfkey_safe_build(error = pfkey_lifetime_build(&extensions[SADB_EXT_LIFETIME_SOFT],
								  SADB_EXT_LIFETIME_SOFT,
								  ipsp->ips_life.ipl_allocations.ipl_soft,
								  ipsp->ips_life.ipl_bytes.ipl_soft,
								  ipsp->ips_life.ipl_addtime.ipl_soft,
								  ipsp->ips_life.ipl_usetime.ipl_soft,
								  ipsp->ips_life.ipl_packets.ipl_soft),
				     extensions))
	      && pfkey_safe_build(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
							      SADB_EXT_ADDRESS_SRC,
							      0, /* ipsp->ips_said.proto, */
							      0,
							      ipsp->ips_addr_s),
				  extensions)
	      && pfkey_safe_build(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST],
							      SADB_EXT_ADDRESS_DST,
							      0, /* ipsp->ips_said.proto, */
							      0,
							      ipsp->ips_addr_d),
				  extensions))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "failed to build the expire message extensions\n");
		spin_unlock(&tdb_lock);
		goto errlab;
	}
	
	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "failed to build the expire message\n");
		SENDERR(-error);
	}
	
	for(pfkey_socketsp = pfkey_open_sockets;
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_msg))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
				    "sending up expire message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "sending up expire message for satype=%d(%s) (proto=%d) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    ipsp->ips_said.proto,
			    pfkey_socketsp->socketp);
	}
	
 errlab:
	if (pfkey_msg) {
		pfkey_msg_free(&pfkey_msg);
	}
	pfkey_extensions_free(extensions);
	return error;
}

int
pfkey_acquire(struct ipsec_sa *ipsp)
{
	struct sadb_ext *extensions[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_msg = NULL;
	struct socket_list *pfkey_socketsp;
	int error = 0;
	struct sadb_comb comb[] = {
		/* auth; encrypt; flags; */
		/* auth_minbits; auth_maxbits; encrypt_minbits; encrypt_maxbits; */
		/* reserved; soft_allocations; hard_allocations; soft_bytes; hard_bytes; */
		/* soft_addtime; hard_addtime; soft_usetime; hard_usetime; */
		/* soft_packets; hard_packets; */
		{ SADB_AALG_MD5_HMAC,  SADB_EALG_3DES_CBC, SADB_SAFLAGS_PFS,
		  128, 128, 168, 168,
		  0, 0, 0, 0, 0,
		  57600, 86400, 57600, 86400,
		  0, 0 },
		{ SADB_AALG_SHA1_HMAC, SADB_EALG_3DES_CBC, SADB_SAFLAGS_PFS,
		  160, 160, 168, 168,
		  0, 0, 0, 0, 0,
		  57600, 86400, 57600, 86400,
		  0, 0 }
	};
       
	/* XXX This should not be hard-coded.  It should be taken from the spdb */
	uint8_t satype = SADB_SATYPE_ESP;

	pfkey_extensions_init(extensions);

	if((satype == 0) || (satype > SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire: "
			    "SAtype=%d unspecified or unknown.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if(!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(1|debug_pfkey, "klips_debug:pfkey_acquire: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}
	
	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions[0],
							  SADB_ACQUIRE,
							  satype,
							  0,
							  ++pfkey_msg_seq,
							  0),
			      extensions)
	      && pfkey_safe_build(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
							      SADB_EXT_ADDRESS_SRC,
							      ipsp->ips_said.proto,
							      0,
							      ipsp->ips_addr_s),
				  extensions)
	      && pfkey_safe_build(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST],
							      SADB_EXT_ADDRESS_DST,
							      ipsp->ips_said.proto,
							      0,
							      ipsp->ips_addr_d),
				  extensions)
#if 0
	      && (ipsp->ips_addr_p
		  ? pfkey_safe_build(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_PROXY],
								 SADB_EXT_ADDRESS_PROXY,
								 ipsp->ips_said.proto,
								 0,
								 ipsp->ips_addr_p),
				     extensions) : 1)
#endif
	      && (ipsp->ips_ident_s.type != SADB_IDENTTYPE_RESERVED
		  ? pfkey_safe_build(error = pfkey_ident_build(&extensions[SADB_EXT_IDENTITY_SRC],
							       SADB_EXT_IDENTITY_SRC,
							       ipsp->ips_ident_s.type,
							       ipsp->ips_ident_s.id,
							       ipsp->ips_ident_s.len,
							       ipsp->ips_ident_s.data),
				     extensions) : 1)

	      && (ipsp->ips_ident_d.type != SADB_IDENTTYPE_RESERVED
		  ? pfkey_safe_build(error = pfkey_ident_build(&extensions[SADB_EXT_IDENTITY_DST],
							       SADB_EXT_IDENTITY_DST,
							       ipsp->ips_ident_d.type,
							       ipsp->ips_ident_d.id,
							       ipsp->ips_ident_d.len,
							       ipsp->ips_ident_d.data),
				     extensions) : 1)
#if 0
	      /* FIXME: This won't work yet because I have not finished
		 it. */
	      && (ipsp->ips_sens_
		  ? pfkey_safe_build(error = pfkey_sens_build(&extensions[SADB_EXT_SENSITIVITY],
							      ipsp->ips_sens_dpd,
							      ipsp->ips_sens_sens_level,
							      ipsp->ips_sens_sens_len,
							      ipsp->ips_sens_sens_bitmap,
							      ipsp->ips_sens_integ_level,
							      ipsp->ips_sens_integ_len,
							      ipsp->ips_sens_integ_bitmap),
				     extensions) : 1)
#endif
	      && pfkey_safe_build(error = pfkey_prop_build(&extensions[SADB_EXT_PROPOSAL],
							   64, /* replay */
							   sizeof(comb)/sizeof(struct sadb_comb),
							   &(comb[0])),
				  extensions)
		)) {
		KLIPS_PRINT(1|debug_pfkey, "klips_debug:pfkey_acquire: "
			    "failed to build the acquire message extensions\n");
		SENDERR(-error);
	}
	
	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_OUT))) {
		KLIPS_PRINT(1|debug_pfkey, "klips_debug:pfkey_acquire: "
			    "failed to build the acquire message\n");
		SENDERR(-error);
	}

#if KLIPS_PFKEY_ACQUIRE_LOSSAGE > 0
	if(sysctl_ipsec_regress_pfkey_lossage) {
		return(0);
	}
#endif	
	
	/* this should go to all registered sockets for that satype only */
	for(pfkey_socketsp = pfkey_registered_sockets[satype];
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_msg))) {
			KLIPS_PRINT(1|debug_pfkey, "klips_debug:pfkey_acquire: "
				    "sending up acquire message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire: "
			    "sending up acquire message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
 errlab:
	if (pfkey_msg) {
		pfkey_msg_free(&pfkey_msg);
	}
	pfkey_extensions_free(extensions);
	return error;
}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
int
pfkey_nat_t_new_mapping(struct ipsec_sa *ipsp, struct sockaddr *ipaddr,
	__u16 sport)
{
	struct sadb_ext *extensions[SADB_EXT_MAX+1];
	struct sadb_msg *pfkey_msg = NULL;
	struct socket_list *pfkey_socketsp;
	int error = 0;
	uint8_t satype = (ipsp->ips_said.proto==IPPROTO_ESP) ? SADB_SATYPE_ESP : 0;

	/* Construct SADB_X_NAT_T_NEW_MAPPING message */

	pfkey_extensions_init(extensions);

	if((satype == 0) || (satype > SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "SAtype=%d unspecified or unknown.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if(!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}

	if (!(pfkey_safe_build
		(error = pfkey_msg_hdr_build(&extensions[0], SADB_X_NAT_T_NEW_MAPPING,
			satype, 0, ++pfkey_msg_seq, 0), extensions)
		/* SA */
		&& pfkey_safe_build
		(error = pfkey_sa_build(&extensions[SADB_EXT_SA],
			SADB_EXT_SA, ipsp->ips_said.spi, 0, 0, 0, 0, 0), extensions)
		/* ADDRESS_SRC = old addr */
		&& pfkey_safe_build
		(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
			SADB_EXT_ADDRESS_SRC, ipsp->ips_said.proto, 0, ipsp->ips_addr_s),
			extensions)
		/* NAT_T_SPORT = old port */
	    && pfkey_safe_build
		(error = pfkey_x_nat_t_port_build(&extensions[SADB_X_EXT_NAT_T_SPORT],
			SADB_X_EXT_NAT_T_SPORT, ipsp->ips_natt_sport), extensions)
		/* ADDRESS_DST = new addr */
		&& pfkey_safe_build
		(error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST],
			SADB_EXT_ADDRESS_DST, ipsp->ips_said.proto, 0, ipaddr), extensions)
		/* NAT_T_DPORT = new port */
	    && pfkey_safe_build
		(error = pfkey_x_nat_t_port_build(&extensions[SADB_X_EXT_NAT_T_DPORT],
			SADB_X_EXT_NAT_T_DPORT, sport), extensions)
		)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "failed to build the nat_t_new_mapping message extensions\n");
		SENDERR(-error);
	}
	
	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "failed to build the nat_t_new_mapping message\n");
		SENDERR(-error);
	}

	/* this should go to all registered sockets for that satype only */
	for(pfkey_socketsp = pfkey_registered_sockets[satype];
	    pfkey_socketsp;
	    pfkey_socketsp = pfkey_socketsp->next) {
		if((error = pfkey_upmsg(pfkey_socketsp->socketp, pfkey_msg))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
				    "sending up nat_t_new_mapping message for satype=%d(%s) to socket=%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "sending up nat_t_new_mapping message for satype=%d(%s) to socket=%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}
	
 errlab:
	if (pfkey_msg) {
		pfkey_msg_free(&pfkey_msg);
	}
	pfkey_extensions_free(extensions);
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_nat_t_new_mapping_parse(struct sock *sk, struct sadb_ext **extensions, struct pfkey_extracted_data* extr)
{
	/* SADB_X_NAT_T_NEW_MAPPING not used in kernel */
	return -EINVAL;
}
#endif

DEBUG_NO_STATIC int (*ext_processors[SADB_EXT_MAX+1])(struct sadb_ext *pfkey_ext, struct pfkey_extracted_data* extr) =
{
  NULL, /* pfkey_msg_process, */
        pfkey_sa_process,
        pfkey_lifetime_process,
        pfkey_lifetime_process,
        pfkey_lifetime_process,
        pfkey_address_process,
        pfkey_address_process,
        pfkey_address_process,
        pfkey_key_process,
        pfkey_key_process,
        pfkey_ident_process,
        pfkey_ident_process,
        pfkey_sens_process,
        pfkey_prop_process,
        pfkey_supported_process,
        pfkey_supported_process,
        pfkey_spirange_process,
        pfkey_x_kmprivate_process,
        pfkey_x_satype_process,
        pfkey_sa_process,
        pfkey_address_process,
        pfkey_address_process,
        pfkey_address_process,
        pfkey_address_process,
        pfkey_address_process,
	pfkey_x_debug_process,
	pfkey_x_protocol_process
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	,
	pfkey_x_nat_t_type_process,
	pfkey_x_nat_t_port_process,
	pfkey_x_nat_t_port_process,
	pfkey_address_process
#endif	
};


DEBUG_NO_STATIC int (*msg_parsers[SADB_MAX +1])(struct sock *sk, struct sadb_ext *extensions[], struct pfkey_extracted_data* extr)
 =
{
	NULL, /* RESERVED */
	pfkey_getspi_parse,
	pfkey_update_parse,
	pfkey_add_parse,
	pfkey_delete_parse,
	pfkey_get_parse,
	pfkey_acquire_parse,
	pfkey_register_parse,
	pfkey_expire_parse,
	pfkey_flush_parse,
	pfkey_dump_parse,
	pfkey_x_promisc_parse,
	pfkey_x_pchange_parse,
	pfkey_x_grpsa_parse,
	pfkey_x_addflow_parse,
	pfkey_x_delflow_parse,
	pfkey_x_msg_debug_parse
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	, pfkey_x_nat_t_new_mapping_parse
#endif	
};

int
pfkey_build_reply(struct sadb_msg *pfkey_msg, struct pfkey_extracted_data *extr,
				struct sadb_msg **pfkey_reply)
{
	struct sadb_ext *extensions[SADB_EXT_MAX+1];
	int error = 0;
	int msg_type = pfkey_msg->sadb_msg_type;
	int seq = pfkey_msg->sadb_msg_seq;

	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_build_reply: "
		    "building reply with type: %d\n",
		    msg_type);
	pfkey_extensions_init(extensions);
	if (!extr || !extr->ips) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_build_reply: "
				    "bad ipsec_sa passed\n");
			return EINVAL;
	}
	error = pfkey_safe_build(pfkey_msg_hdr_build(&extensions[0],
						     msg_type,
						     proto2satype(extr->ips->ips_said.proto),
						     0,
						     seq,
						     pfkey_msg->sadb_msg_pid),
				 extensions) &&
		(!(extensions_bitmaps[EXT_BITS_OUT][EXT_BITS_REQ][msg_type] &
		   1 << SADB_EXT_SA)
		 || pfkey_safe_build(pfkey_sa_ref_build(&extensions[SADB_EXT_SA],
						    SADB_EXT_SA,
						    extr->ips->ips_said.spi,
						    extr->ips->ips_replaywin,
						    extr->ips->ips_state,
						    extr->ips->ips_authalg,
						    extr->ips->ips_encalg,
						    extr->ips->ips_flags,
						    extr->ips->ips_ref),
				     extensions)) &&
		(!(extensions_bitmaps[EXT_BITS_OUT][EXT_BITS_REQ][msg_type] &
		   1 << SADB_EXT_LIFETIME_CURRENT)
		 || pfkey_safe_build(pfkey_lifetime_build(&extensions
							  [SADB_EXT_LIFETIME_CURRENT],
							  SADB_EXT_LIFETIME_CURRENT,
							  extr->ips->ips_life.ipl_allocations.ipl_count,
							  extr->ips->ips_life.ipl_bytes.ipl_count,
							  extr->ips->ips_life.ipl_addtime.ipl_count,
							  extr->ips->ips_life.ipl_usetime.ipl_count,
							  extr->ips->ips_life.ipl_packets.ipl_count),
				     extensions)) &&
		(!(extensions_bitmaps[EXT_BITS_OUT][EXT_BITS_REQ][msg_type] &
		   1 << SADB_EXT_ADDRESS_SRC)
		 || pfkey_safe_build(pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
							 SADB_EXT_ADDRESS_SRC,
							 extr->ips->ips_said.proto,
							 0,
							 extr->ips->ips_addr_s),
				     extensions)) &&
		(!(extensions_bitmaps[EXT_BITS_OUT][EXT_BITS_REQ][msg_type] &
		   1 << SADB_EXT_ADDRESS_DST)
		 || pfkey_safe_build(pfkey_address_build(&extensions[SADB_EXT_ADDRESS_DST],
							 SADB_EXT_ADDRESS_DST,
							 extr->ips->ips_said.proto,
							 0,
							 extr->ips->ips_addr_d),
				     extensions));

	if (error == 0) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_build_reply: "
			    "building extensions failed\n");
		return EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_build_reply: "
		    "built extensions, proceed to build the message\n");
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_build_reply: "
		    "extensions[1]=0p%p\n",
		    extensions[1]);
	error = pfkey_msg_build(pfkey_reply, extensions, EXT_BITS_OUT);
	pfkey_extensions_free(extensions);

	return error;
}

int
pfkey_msg_interp(struct sock *sk, struct sadb_msg *pfkey_msg,
				struct sadb_msg **pfkey_reply)
{
	int error = 0;
	int i;
	struct sadb_ext *extensions[SADB_EXT_MAX+1];
	struct pfkey_extracted_data extr = {NULL, NULL, NULL};
	
	pfkey_extensions_init(extensions);
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_msg_interp: "
		    "parsing message ver=%d, type=%d, errno=%d, satype=%d(%s), len=%d, res=%d, seq=%d, pid=%d.\n", 
		    pfkey_msg->sadb_msg_version,
		    pfkey_msg->sadb_msg_type,
		    pfkey_msg->sadb_msg_errno,
		    pfkey_msg->sadb_msg_satype,
		    satype2name(pfkey_msg->sadb_msg_satype),
		    pfkey_msg->sadb_msg_len,
		    pfkey_msg->sadb_msg_reserved,
		    pfkey_msg->sadb_msg_seq,
		    pfkey_msg->sadb_msg_pid);
	
	extr.ips = ipsec_sa_alloc(&error); /* pass in error var by pointer */
	if(extr.ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "memory allocation error.\n");
		SENDERR(-error);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_msg_interp: "
		    "allocated extr->ips=0p%p.\n",
		    extr.ips);
	
	if(pfkey_msg->sadb_msg_satype > SADB_SATYPE_MAX) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "satype %d > max %d\n", 
			    pfkey_msg->sadb_msg_satype,
			    SADB_SATYPE_MAX);
		SENDERR(EINVAL);
	}
	
	switch(pfkey_msg->sadb_msg_type) {
	case SADB_GETSPI:
	case SADB_UPDATE:
	case SADB_ADD:
	case SADB_DELETE:
	case SADB_X_GRPSA:
	case SADB_X_ADDFLOW:
		if(!(extr.ips->ips_said.proto = satype2proto(pfkey_msg->sadb_msg_satype))) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_msg_interp: "
				    "satype %d lookup failed.\n", 
				    pfkey_msg->sadb_msg_satype);
			SENDERR(EINVAL);
		} else {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_msg_interp: "
				    "satype %d lookups to proto=%d.\n", 
				    pfkey_msg->sadb_msg_satype,
				    extr.ips->ips_said.proto);
		}
		break;
	default:
		break;
	}
	
	/* The NULL below causes the default extension parsers to be used */
	/* Parse the extensions */
	if((error = pfkey_msg_parse(pfkey_msg, NULL, extensions, EXT_BITS_IN)))
	{
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "message parsing failed with error %d.\n",
			    error); 
		SENDERR(-error);
	}
	
	/* Process the extensions */
	for(i=1; i <= SADB_EXT_MAX;i++)	{
		if(extensions[i] != NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_msg_interp: "
				    "processing ext %d 0p%p with processor 0p%p.\n", 
				    i, extensions[i], ext_processors[i]);
			if((error = ext_processors[i](extensions[i], &extr))) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_msg_interp: "
					    "extension processing for type %d failed with error %d.\n",
					    i,
					    error); 
				SENDERR(-error);
			}
			
		}
		
	}
	
	/* Parse the message types */
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_msg_interp: "
		    "parsing message type %d(%s) with msg_parser 0p%p.\n",
		    pfkey_msg->sadb_msg_type,
		    pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type),
		    msg_parsers[pfkey_msg->sadb_msg_type]); 
	if((error = msg_parsers[pfkey_msg->sadb_msg_type](sk, extensions, &extr))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "message parsing failed with error %d.\n",
			    error); 
		SENDERR(-error);
	}

#if 0
	error = pfkey_build_reply(pfkey_msg, &extr, pfkey_reply);
	if (error) {
		*pfkey_reply = NULL;
	}
#endif	
 errlab:
	if(extr.ips != NULL) {
		ipsec_sa_wipe(extr.ips);
	}
	if(extr.ips2 != NULL) {
		ipsec_sa_wipe(extr.ips2);
	}
	if (extr.eroute != NULL) {
		kfree(extr.eroute);
	}
	return(error);
}

