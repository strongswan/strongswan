/*
 * receive code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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

char ipsec_rcv_c_version[] = "RCSID $Id: ipsec_rcv.c,v 1.5 2005/04/10 21:38:32 as Exp $";

#include <linux/config.h>
#include <linux/version.h>

#define __NO_VERSION__
#include <linux/module.h>
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

#include <linux/netdevice.h>	/* struct device, and other headers */
#include <linux/etherdevice.h>	/* eth_type_trans */
#include <linux/ip.h>		/* struct iphdr */
#include <linux/skbuff.h>
#include <freeswan.h>
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
# define proto_priv cb
#endif /* NET21 */
#include <asm/checksum.h>
#include <net/ip.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_sa.h"

#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_tunnel.h"
#include "freeswan/ipsec_rcv.h"

#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
#include "freeswan/ipsec_ah.h"
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */

#ifdef CONFIG_IPSEC_ESP
#include "freeswan/ipsec_esp.h"
#endif /* !CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_IPCOMP
#include "freeswan/ipcomp.h"
#endif /* CONFIG_IPSEC_COMP */

#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/ipsec_proto.h"
#include "freeswan/ipsec_alg.h"

#ifdef CONFIG_IPSEC_DEBUG
int debug_ah = 0;
int debug_esp = 0;
int debug_rcv = 0;
#endif /* CONFIG_IPSEC_DEBUG */

int sysctl_ipsec_inbound_policy_check = 1;

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

#ifdef CONFIG_IPSEC_DEBUG
static void
rcv_dmp(char *s, caddr_t bb, int len)
{
	int i;
	unsigned char *b = bb;
  
	if (debug_rcv && sysctl_ipsec_debug_verbose) {
		printk(KERN_INFO "klips_debug:ipsec_tunnel_:dmp: "
		       "at %s, len=%d:",
		       s,
		       len);
		for (i=0; i < len; i++) {
			if(!(i%16)){
				printk("\nklips_debug:  ");
			}
			printk(" %02x", *b++);
		}
		printk("\n");
	}
}
#else /* CONFIG_IPSEC_DEBUG */
#define rcv_dmp(_x, _y, _z) 
#endif /* CONFIG_IPSEC_DEBUG */


#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
__u32 zeroes[AH_AMAX];
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */

/*
 * Check-replay-window routine, adapted from the original
 * by J. Hughes, from draft-ietf-ipsec-esp-des-md5-03.txt
 *
 *  This is a routine that implements a 64 packet window. This is intend-
 *  ed on being an implementation sample.
 */

DEBUG_NO_STATIC int
ipsec_checkreplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	return 1;			/* out of order but good */
}

DEBUG_NO_STATIC int
ipsec_updatereplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		diff = seq - ipsp->ips_replaywin_lastseq;

		/* In win, set bit for this pkt */
		if (diff < ipsp->ips_replaywin)
			ipsp->ips_replaywin_bitmap =
				(ipsp->ips_replaywin_bitmap << diff) | 1;
		else
			/* This packet has way larger seq num */
			ipsp->ips_replaywin_bitmap = 1;

		if(seq - ipsp->ips_replaywin_lastseq - 1 > ipsp->ips_replaywin_maxdiff) {
			ipsp->ips_replaywin_maxdiff = seq - ipsp->ips_replaywin_lastseq - 1;
		}
		ipsp->ips_replaywin_lastseq = seq;
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
/*
		if(seq < 0.25*max && ipsp->ips_replaywin_lastseq > 0.75*max) {
			ipsec_sa_delchain(ipsp);
		}
*/
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	ipsp->ips_replaywin_bitmap |= (1 << diff);	/* mark as seen */
	return 1;			/* out of order but good */
}

#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
struct auth_alg ipsec_rcv_md5[]={
	{MD5Init, MD5Update, MD5Final, AHMD596_ALEN}
};

#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */

#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
struct auth_alg ipsec_rcv_sha1[]={
	{SHA1Init, SHA1Update, SHA1Final, AHSHA196_ALEN}
};
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */

enum ipsec_rcv_value {
	IPSEC_RCV_LASTPROTO=1,
	IPSEC_RCV_OK=0,
	IPSEC_RCV_BADPROTO=-1,
	IPSEC_RCV_BADLEN=-2,
	IPSEC_RCV_ESP_BADALG=-3,
	IPSEC_RCV_3DES_BADBLOCKING=-4,
	IPSEC_RCV_ESP_DECAPFAIL=-5,
	IPSEC_RCV_DECAPFAIL=-6,
	IPSEC_RCV_SAIDNOTFOUND=-7,
	IPSEC_RCV_IPCOMPALONE=-8,
	IPSEC_RCV_IPCOMPFAILED=-10,
	IPSEC_RCV_SAIDNOTLIVE=-11,
	IPSEC_RCV_FAILEDINBOUND=-12,
	IPSEC_RCV_LIFETIMEFAILED=-13,
	IPSEC_RCV_BADAUTH=-14,
	IPSEC_RCV_REPLAYFAILED=-15,
	IPSEC_RCV_AUTHFAILED=-16,
	IPSEC_RCV_REPLAYROLLED=-17,
	IPSEC_RCV_BAD_DECRYPT=-18
};

struct ipsec_rcv_state {
	struct sk_buff *skb;
	struct net_device_stats *stats;
	struct iphdr *ipp;
	struct ipsec_sa *ipsp;
	int len;
	int ilen;
	int authlen;
	int hard_header_len;
	int iphlen;
	struct auth_alg *authfuncs;
	struct sa_id said;
	char   sa[SATOA_BUF];
	size_t sa_len;
	__u8 next_header;
	__u8 hash[AH_AMAX];
	char ipsaddr_txt[ADDRTOA_BUF];
	char ipdaddr_txt[ADDRTOA_BUF];
	__u8 *octx;
	__u8 *ictx;
	int ictx_len;
	int octx_len;
	union {
		struct {
			struct esphdr *espp;
		} espstuff;
		struct {
			struct ahhdr *ahp;
		} ahstuff;
		struct {
			struct ipcomphdr *compp;
		} ipcompstuff;
	} protostuff;
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	__u16 natt_len;
	__u16 natt_sport;
	__u16 natt_dport;
	__u8 natt_type;
#endif	
};

struct xform_functions {
	enum ipsec_rcv_value (*checks)(struct ipsec_rcv_state *irs,
				       struct sk_buff *skb);
        enum ipsec_rcv_value (*decrypt)(struct ipsec_rcv_state *irs);

	enum ipsec_rcv_value (*setup_auth)(struct ipsec_rcv_state *irs,
					   struct sk_buff *skb,
					   __u32          *replay,
					   unsigned char **authenticator);
	enum ipsec_rcv_value (*calc_auth)(struct ipsec_rcv_state *irs,
					struct sk_buff *skb);
};

#ifdef CONFIG_IPSEC_ESP
enum ipsec_rcv_value
ipsec_rcv_esp_checks(struct ipsec_rcv_state *irs,
		     struct sk_buff *skb)
{
	__u8 proto;
	int len;	/* packet length */

	len = skb->len;
	proto = irs->ipp->protocol;

	/* XXX this will need to be 8 for IPv6 */
	if ((proto == IPPROTO_ESP) && ((len - irs->iphlen) % 4)) {
		printk("klips_error:ipsec_rcv: "
		       "got packet with content length = %d from %s -- should be on 4 octet boundary, packet dropped\n",
		       len - irs->iphlen,
		       irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	if(skb->len < (irs->hard_header_len + sizeof(struct iphdr) + sizeof(struct esphdr))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt esp packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	irs->protostuff.espstuff.espp = (struct esphdr *)(skb->data + irs->iphlen);
	irs->said.spi = irs->protostuff.espstuff.espp->esp_spi;

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_esp_decrypt_setup(struct ipsec_rcv_state *irs,
			    struct sk_buff *skb,
			    __u32          *replay,
			    unsigned char **authenticator)
{
	struct esphdr *espp = irs->protostuff.espstuff.espp;

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "packet from %s received with seq=%d (iv)=0x%08x%08x iplen=%d esplen=%d sa=%s\n",
		    irs->ipsaddr_txt,
		    (__u32)ntohl(espp->esp_rpl),
		    (__u32)ntohl(*((__u32 *)(espp->esp_iv)    )),
		    (__u32)ntohl(*((__u32 *)(espp->esp_iv) + 1)),
		    irs->len,
		    irs->ilen,
		    irs->sa_len ? irs->sa : " (error)");

	*replay = ntohl(espp->esp_rpl);
	*authenticator = &(skb->data[irs->len - irs->authlen]);

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_esp_authcalc(struct ipsec_rcv_state *irs,
		       struct sk_buff *skb)
{
	struct auth_alg *aa;
	struct esphdr *espp = irs->protostuff.espstuff.espp;
	union {
		MD5_CTX		md5;
		SHA1_CTX	sha1;
	} tctx;

#ifdef CONFIG_IPSEC_ALG
	if (irs->ipsp->ips_alg_auth) {
		KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"ipsec_alg hashing proto=%d... ",
				irs->said.proto);
		if(irs->said.proto == IPPROTO_ESP) {
			ipsec_alg_sa_esp_hash(irs->ipsp,
					(caddr_t)espp, irs->ilen,
					irs->hash, AHHMAC_HASHLEN);
			return IPSEC_RCV_OK;
		}
		return IPSEC_RCV_BADPROTO;
	}
#endif
	aa = irs->authfuncs;

	/* copy the initialized keying material */
	memcpy(&tctx, irs->ictx, irs->ictx_len);

	(*aa->update)((void *)&tctx, (caddr_t)espp, irs->ilen);

	(*aa->final)(irs->hash, (void *)&tctx);

	memcpy(&tctx, irs->octx, irs->octx_len);

	(*aa->update)((void *)&tctx, irs->hash, aa->hashlen);
	(*aa->final)(irs->hash, (void *)&tctx);

	return IPSEC_RCV_OK;
}


enum ipsec_rcv_value
ipsec_rcv_esp_decrypt(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *ipsp = irs->ipsp;
	struct esphdr *espp = irs->protostuff.espstuff.espp;
	int esphlen = 0;
	__u8 *idat;	/* pointer to content to be decrypted/authenticated */
#ifdef CONFIG_IPSEC_ENC_3DES
	__u32 iv[2];
#endif /* !CONFIG_IPSEC_ENC_3DES */
	int pad = 0, padlen;
	int badpad = 0;
	int i;
	struct sk_buff *skb;
#ifdef CONFIG_IPSEC_ALG
	struct ipsec_alg_enc *ixt_e=NULL;
#endif /* CONFIG_IPSEC_ALG */

	skb=irs->skb;

	idat = skb->data + irs->iphlen;

#ifdef CONFIG_IPSEC_ALG
	if ((ixt_e=ipsp->ips_alg_enc)) {
		esphlen = ESP_HEADER_LEN + ixt_e->ixt_ivlen/8;
		KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"encalg=%d esphlen=%d\n",
				ipsp->ips_encalg, esphlen);
	} else
#endif /* CONFIG_IPSEC_ALG */
	switch(ipsp->ips_encalg) {
#ifdef CONFIG_IPSEC_ENC_3DES
	case ESP_3DES:
		iv[0] = *((__u32 *)(espp->esp_iv)    );
		iv[1] = *((__u32 *)(espp->esp_iv) + 1);
		esphlen = sizeof(struct esphdr);
		break;
#endif /* !CONFIG_IPSEC_ENC_3DES */
	default:
		ipsp->ips_errs.ips_alg_errs += 1;
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_ESP_BADALG;
	}

	idat += esphlen;
	irs->ilen -= esphlen;

#ifdef CONFIG_IPSEC_ALG
	if (ixt_e)
	{
		if (ipsec_alg_esp_encrypt(ipsp,
					idat, irs->ilen, espp->esp_iv,
					IPSEC_ALG_DECRYPT) <= 0)
		{
			printk("klips_error:ipsec_rcv: "
					"got packet with esplen = %d "
					"from %s -- should be on "
					"ENC(%d) octet boundary, "
					"packet dropped\n",
					irs->ilen,
					irs->ipsaddr_txt,
					ipsp->ips_encalg);
			if(irs->stats) {
				irs->stats->rx_errors++;
			}
			return IPSEC_RCV_BAD_DECRYPT;
		}
	} else
#endif /* CONFIG_IPSEC_ALG */
	switch(ipsp->ips_encalg) {
#ifdef CONFIG_IPSEC_ENC_3DES
	case ESP_3DES:
		if ((irs->ilen) % 8) {
			ipsp->ips_errs.ips_encsize_errs += 1;
			printk("klips_error:ipsec_rcv: "
			       "got packet with esplen = %d from %s -- should be on 8 octet boundary, packet dropped\n",
			       irs->ilen,
			       irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_errors++;
			}
			return IPSEC_RCV_3DES_BADBLOCKING;
		}
		des_ede3_cbc_encrypt((des_cblock *)idat,
				     (des_cblock *)idat,
				     irs->ilen,
				     ((struct des_eks *)(ipsp->ips_key_e))[0].ks,
				     ((struct des_eks *)(ipsp->ips_key_e))[1].ks,
				     ((struct des_eks *)(ipsp->ips_key_e))[2].ks,
				     (des_cblock *)iv, 0);
		break;
#endif /* !CONFIG_IPSEC_ENC_3DES */
	}

	rcv_dmp("postdecrypt", skb->data, skb->len);

	irs->next_header = idat[irs->ilen - 1];
	padlen = idat[irs->ilen - 2];
	pad = padlen + 2 + irs->authlen;

	KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
		    "klips_debug:ipsec_rcv: "
		    "padlen=%d, contents: 0x<offset>: 0x<value> 0x<value> ...\n",
		    padlen);

	for (i = 1; i <= padlen; i++) {
		if((i % 16) == 1) {
			KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
				    "klips_debug:           %02x:",
				    i - 1);
		}
		KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				" %02x",
				idat[irs->ilen - 2 - padlen + i - 1]);
		if(i != idat[irs->ilen - 2 - padlen + i - 1]) {
			badpad = 1;
		}
		if((i % 16) == 0) {
			KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
					"\n");
		}
	}
	if((i % 16) != 1) {
		KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
						"\n");
	}
	if(badpad) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv: "
			    "warning, decrypted packet from %s has bad padding\n",
			    irs->ipsaddr_txt);
		KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv: "
			    "...may be bad decryption -- not dropped\n");
		ipsp->ips_errs.ips_encpad_errs += 1;
	}

	KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
		    "klips_debug:ipsec_rcv: "
		    "packet decrypted from %s: next_header = %d, padding = %d\n",
		    irs->ipsaddr_txt,
		    irs->next_header,
		    pad - 2 - irs->authlen);

	irs->ipp->tot_len = htons(ntohs(irs->ipp->tot_len) - (esphlen + pad));

	/*
	 * move the IP header forward by the size of the ESP header, which
	 * will remove the the ESP header from the packet.
	 */
	memmove((void *)(skb->data + esphlen),
		(void *)(skb->data), irs->iphlen);

	rcv_dmp("esp postmove", skb->data, skb->len);

	/* skb_pull below, will move up by esphlen */

	/* XXX not clear how this can happen, as the message indicates */
	if(skb->len < esphlen) {
		printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "tried to skb_pull esphlen=%d, %d available.  This should never happen, please report.\n",
		       esphlen, (int)(skb->len));
		return IPSEC_RCV_ESP_DECAPFAIL;
	}
	skb_pull(skb, esphlen);

	irs->ipp = (struct iphdr *)skb->data;

	rcv_dmp("esp postpull", skb->data, skb->len);

	/* now, trip off the padding from the end */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "trimming to %d.\n",
		    irs->len - esphlen - pad);
	if(pad + esphlen <= irs->len) {
		skb_trim(skb, irs->len - esphlen - pad);
	} else {
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "bogus packet, size is zero or negative, dropping.\n");
		return IPSEC_RCV_DECAPFAIL;
	}

	return IPSEC_RCV_OK;
}


struct xform_functions esp_rcv_funcs[]={
	{	checks:         ipsec_rcv_esp_checks,
		setup_auth:     ipsec_rcv_esp_decrypt_setup,
		calc_auth:      ipsec_rcv_esp_authcalc,
		decrypt:        ipsec_rcv_esp_decrypt,
	},
};
#endif /* !CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_AH
enum ipsec_rcv_value
ipsec_rcv_ah_checks(struct ipsec_rcv_state *irs,
		    struct sk_buff *skb)
{
	int ahminlen;

	ahminlen = irs->hard_header_len + sizeof(struct iphdr);

	/* take care not to deref this pointer until we check the minlen though */
	irs->protostuff.ahstuff.ahp = (struct ahhdr *) (skb->data + irs->iphlen);

	if((skb->len < ahminlen+sizeof(struct ahhdr)) ||
	   (skb->len < ahminlen+(irs->protostuff.ahstuff.ahp->ah_hl << 2))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt ah packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	irs->said.spi = irs->protostuff.ahstuff.ahp->ah_spi;

	/* XXX we only support the one 12-byte authenticator for now */
	if(irs->protostuff.ahstuff.ahp->ah_hl != ((AHHMAC_HASHLEN+AHHMAC_RPLLEN) >> 2)) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "bad authenticator length %ld, expected %lu from %s.\n",
			    (long)(irs->protostuff.ahstuff.ahp->ah_hl << 2),
			    (unsigned long) sizeof(struct ahhdr),
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	return IPSEC_RCV_OK;
}


enum ipsec_rcv_value
ipsec_rcv_ah_setup_auth(struct ipsec_rcv_state *irs,
			struct sk_buff *skb,
			__u32          *replay,
			unsigned char **authenticator)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;

	*replay = ntohl(ahp->ah_rpl);
	*authenticator = ahp->ah_data;

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_ah_authcalc(struct ipsec_rcv_state *irs,
		      struct sk_buff *skb)
{
	struct auth_alg *aa;
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;
	union {
		MD5_CTX		md5;
		SHA1_CTX	sha1;
	} tctx;
	struct iphdr ipo;
	int ahhlen;

	aa = irs->authfuncs;

	/* copy the initialized keying material */
	memcpy(&tctx, irs->ictx, irs->ictx_len);

	ipo = *irs->ipp;
	ipo.tos = 0;	/* mutable RFC 2402 3.3.3.1.1.1 */
	ipo.frag_off = 0;
	ipo.ttl = 0;
	ipo.check = 0;


	/* do the sanitized header */
	(*aa->update)((void*)&tctx, (caddr_t)&ipo, sizeof(struct iphdr));

	/* XXX we didn't do the options here! */

	/* now do the AH header itself */
	ahhlen = AH_BASIC_LEN + (ahp->ah_hl << 2);
	(*aa->update)((void*)&tctx, (caddr_t)ahp,  ahhlen - AHHMAC_HASHLEN);

	/* now, do some zeroes */
	(*aa->update)((void*)&tctx, (caddr_t)zeroes,  AHHMAC_HASHLEN);

	/* finally, do the packet contents themselves */
	(*aa->update)((void*)&tctx,
		      (caddr_t)skb->data + irs->iphlen + ahhlen,
		      skb->len - irs->iphlen - ahhlen);

	(*aa->final)(irs->hash, (void *)&tctx);

	memcpy(&tctx, irs->octx, irs->octx_len);

	(*aa->update)((void *)&tctx, irs->hash, aa->hashlen);
	(*aa->final)(irs->hash, (void *)&tctx);

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_ah_decap(struct ipsec_rcv_state *irs)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;
	struct sk_buff *skb;
	int ahhlen;

	skb=irs->skb;

	ahhlen = AH_BASIC_LEN + (ahp->ah_hl << 2);

	irs->ipp->tot_len = htons(ntohs(irs->ipp->tot_len) - ahhlen);
	irs->next_header  = ahp->ah_nh;

	/*
	 * move the IP header forward by the size of the AH header, which
	 * will remove the the AH header from the packet.
	 */
	memmove((void *)(skb->data + ahhlen),
		(void *)(skb->data), irs->iphlen);

	rcv_dmp("ah postmove", skb->data, skb->len);

	/* skb_pull below, will move up by ahhlen */

	/* XXX not clear how this can happen, as the message indicates */
	if(skb->len < ahhlen) {
		printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "tried to skb_pull ahhlen=%d, %d available.  This should never happen, please report.\n",
		       ahhlen,
		       (int)(skb->len));
		return IPSEC_RCV_DECAPFAIL;
	}
	skb_pull(skb, ahhlen);

	irs->ipp = (struct iphdr *)skb->data;

	rcv_dmp("ah postpull", skb->data, skb->len);

	return IPSEC_RCV_OK;
}


struct xform_functions ah_rcv_funcs[]={
	{	checks:         ipsec_rcv_ah_checks,
		setup_auth:     ipsec_rcv_ah_setup_auth,
		calc_auth:      ipsec_rcv_ah_authcalc,
		decrypt:        ipsec_rcv_ah_decap,
	},
};

#endif /* CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_IPCOMP
enum ipsec_rcv_value
ipsec_rcv_ipcomp_checks(struct ipsec_rcv_state *irs,
			struct sk_buff *skb)
{
	int ipcompminlen;

	ipcompminlen = irs->hard_header_len + sizeof(struct iphdr);

	if(skb->len < (ipcompminlen + sizeof(struct ipcomphdr))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt comp packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADLEN;
	}

	irs->protostuff.ipcompstuff.compp = (struct ipcomphdr *)(skb->data + irs->iphlen);
	irs->said.spi = htonl((__u32)ntohs(irs->protostuff.ipcompstuff.compp->ipcomp_cpi));
	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value
ipsec_rcv_ipcomp_decomp(struct ipsec_rcv_state *irs)
{
	unsigned int flags = 0;
	struct ipsec_sa *ipsp = irs->ipsp;
	struct sk_buff *skb;

	skb=irs->skb;

	rcv_dmp("ipcomp", skb->data, skb->len);

	if(ipsp == NULL) {
		return IPSEC_RCV_SAIDNOTFOUND;
	}

#if 0
	/* we want to check that this wasn't the first SA on the list, because
	 * we don't support bare IPCOMP, for unexplained reasons. MCR
	 */
	if (ipsp->ips_onext != NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "Incoming packet with outer IPCOMP header SA:%s: not yet supported by KLIPS, dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}

		return IPSEC_RCV_IPCOMPALONE;
	}
#endif

	if(sysctl_ipsec_inbound_policy_check &&
	   ((((ntohl(ipsp->ips_said.spi) & 0x0000ffff) != ntohl(irs->said.spi)) &&
	     (ipsp->ips_encalg != ntohl(irs->said.spi))   /* this is a workaround for peer non-compliance with rfc2393 */
		    ))) {
		char sa2[SATOA_BUF];
		size_t sa_len2 = 0;

		sa_len2 = satoa(ipsp->ips_said, 0, sa2, SATOA_BUF);

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "Incoming packet with SA(IPCA):%s does not match policy SA(IPCA):%s cpi=%04x cpi->spi=%08x spi=%08x, spi->cpi=%04x for SA grouping, dropped.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    ipsp != NULL ? (sa_len2 ? sa2 : " (error)") : "NULL",
			    ntohs(irs->protostuff.ipcompstuff.compp->ipcomp_cpi),
			    (__u32)ntohl(irs->said.spi),
			    ipsp != NULL ? (__u32)ntohl((ipsp->ips_said.spi)) : 0,
			    ipsp != NULL ? (__u16)(ntohl(ipsp->ips_said.spi) & 0x0000ffff) : 0);
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	ipsp->ips_comp_ratio_cbytes += ntohs(irs->ipp->tot_len);
	irs->next_header = irs->protostuff.ipcompstuff.compp->ipcomp_nh;

	skb = skb_decompress(skb, ipsp, &flags);
	if (!skb || flags) {
		spin_unlock(&tdb_lock);
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "skb_decompress() returned error flags=%x, dropped.\n",
			    flags);
		if (irs->stats) {
			if (flags)
				irs->stats->rx_errors++;
			else
				irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_IPCOMPFAILED;
	}

	/* make sure we update the pointer */
	irs->skb = skb;
	
#ifdef NET_21
	irs->ipp = skb->nh.iph;
#else /* NET_21 */
	irs->ipp = skb->ip_hdr;
#endif /* NET_21 */

	ipsp->ips_comp_ratio_dbytes += ntohs(irs->ipp->tot_len);

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "packet decompressed SA(IPCA):%s cpi->spi=%08x spi=%08x, spi->cpi=%04x, nh=%d.\n",
		    irs->sa_len ? irs->sa : " (error)",
		    (__u32)ntohl(irs->said.spi),
		    ipsp != NULL ? (__u32)ntohl((ipsp->ips_said.spi)) : 0,
		    ipsp != NULL ? (__u16)(ntohl(ipsp->ips_said.spi) & 0x0000ffff) : 0,
		    irs->next_header);
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, irs->ipp);

	return IPSEC_RCV_OK;
}


struct xform_functions ipcomp_rcv_funcs[]={
	{checks:  ipsec_rcv_ipcomp_checks,
	 decrypt: ipsec_rcv_ipcomp_decomp,
	},
};

#endif /* CONFIG_IPSEC_IPCOMP */

enum ipsec_rcv_value
ipsec_rcv_decap_once(struct ipsec_rcv_state *irs)
{
	int iphlen;
	unsigned char *dat;
	__u8 proto;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	int replay = 0;	/* replay value in AH or ESP packet */
	struct ipsec_sa* ipsnext = NULL;	/* next SA towards inside of packet */
	struct xform_functions *proto_funcs;
	struct ipsec_sa *newipsp;
	struct iphdr *ipp;
	struct sk_buff *skb;
#ifdef CONFIG_IPSEC_ALG
	struct ipsec_alg_auth *ixt_a=NULL;
#endif /* CONFIG_IPSEC_ALG */

	skb = irs->skb;
	irs->len = skb->len;
	dat = skb->data;
	ipp = irs->ipp;
	proto = ipp->protocol;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));

	iphlen = ipp->ihl << 2;
	irs->iphlen=iphlen;
	ipp->check = 0;			/* we know the sum is good */
	
	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv_decap_once: "
		    "decap (%d) from %s -> %s\n",
		    proto, irs->ipsaddr_txt, irs->ipdaddr_txt);

	switch(proto) {
#ifdef CONFIG_IPSEC_ESP
	case IPPROTO_ESP:
		proto_funcs = esp_rcv_funcs;
		break;
#endif /* !CONFIG_IPSEC_ESP */

#ifdef CONFIG_IPSEC_AH
	case IPPROTO_AH:
		proto_funcs = ah_rcv_funcs;
		break;
#endif /* !CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_IPCOMP
	case IPPROTO_COMP:
		proto_funcs = ipcomp_rcv_funcs;
		break;
#endif /* !CONFIG_IPSEC_IPCOMP */
	default:
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADPROTO;
	}

	/*
	 * Find tunnel control block and (indirectly) call the
	 * appropriate tranform routine. The resulting sk_buf
	 * is a valid IP packet ready to go through input processing.
	 */

	irs->said.dst.s_addr = ipp->daddr;

	if(proto_funcs->checks) {
		enum ipsec_rcv_value retval = (*proto_funcs->checks)(irs, skb);

		if(retval < 0) {
			return retval;
		}
	}

	irs->said.proto = proto;
	irs->sa_len = satoa(irs->said, 0, irs->sa, SATOA_BUF);
	if(irs->sa_len == 0) {
		strcpy(irs->sa, "(error)");
	}

	newipsp = ipsec_sa_getbyid(&irs->said);
	if (newipsp == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "no ipsec_sa for SA:%s: incoming packet with no SA dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	/* MCR - XXX this is bizarre. ipsec_sa_getbyid returned it, having incremented the refcount,
	 * why in the world would we decrement it here?

	 ipsec_sa_put(irs->ipsp);*/ /* incomplete */

	/* If it is in larval state, drop the packet, we cannot process yet. */
	if(newipsp->ips_state == SADB_SASTATE_LARVAL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in larval state, cannot be used yet, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(newipsp->ips_state == SADB_SASTATE_DEAD) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in dead state, cannot be used any more, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(sysctl_ipsec_inbound_policy_check) {
		if(irs->ipp->saddr != ((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    irs->ipsaddr_txt);

		/*
		 * at this point, we have looked up a new SA, and we want to make sure that if this
		 * isn't the first SA in the list, that the previous SA actually points at this one.
		 */
		if(irs->ipsp) {
			if(irs->ipsp->ips_inext != newipsp) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s: does not agree with ips->inext policy, dropped\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				ipsec_sa_put(newipsp);
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s grouping from previous SA is OK.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s First SA in group.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}

		/*
		 * previously, at this point, we checked if the back pointer from the new SA that
		 * we just found matched the back pointer. But, we won't do this check anymore,
		 * because we want to be able to nest SAs
		 */
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
		KLIPS_PRINT(debug_rcv,
			"klips_debug:ipsec_rcv: "
			"natt_type=%u tdbp->ips_natt_type=%u : %s\n",
			irs->natt_type, newipsp->ips_natt_type,
			(irs->natt_type==newipsp->ips_natt_type)?"ok":"bad");
		if (irs->natt_type != newipsp->ips_natt_type) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s does not agree with expected NAT-T policy.\n",
				    irs->sa_len ? irs->sa : " (error)");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}
#endif		 
	}

	/* okay, SA checks out, so free any previous SA, and record a new one */

	if(irs->ipsp) {
		ipsec_sa_put(irs->ipsp);
	}
	irs->ipsp=newipsp;

	/* note that the outer code will free the irs->ipsp if there is an error */


	/* now check the lifetimes */
	if(ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_bytes,   "bytes",  irs->sa,
				ipsec_life_countbased, ipsec_incoming, irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "addtime",irs->sa,
				ipsec_life_timebased,  ipsec_incoming, irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "usetime",irs->sa,
				ipsec_life_timebased,  ipsec_incoming, irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_packets, "packets",irs->sa,
				ipsec_life_countbased, ipsec_incoming, irs->ipsp) == ipsec_life_harddied) {
		ipsec_sa_delchain(irs->ipsp);
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_decap_once: "
			    "decap (%d) failed lifetime check\n",
			    proto);

		return IPSEC_RCV_LIFETIMEFAILED;
	}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((irs->natt_type) &&
		( (irs->ipp->saddr != (((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr)) ||
		  (irs->natt_sport != newipsp->ips_natt_sport)
		)) {
		struct sockaddr sipaddr;
		/** Advertise NAT-T addr change to pluto **/
		sipaddr.sa_family = AF_INET;
		((struct sockaddr_in*)&sipaddr)->sin_addr.s_addr = irs->ipp->saddr;
		((struct sockaddr_in*)&sipaddr)->sin_port = htons(irs->natt_sport);
		pfkey_nat_t_new_mapping(newipsp, &sipaddr, irs->natt_sport);
		/**
		 * Then allow or block packet depending on
		 * sysctl_ipsec_inbound_policy_check.
		 *
		 * In all cases, pluto will update SA if new mapping is
		 * accepted.
		 */
		if (sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"SA:%s, src=%s:%u of pkt does not agree with expected "
				"SA source address policy (pluto has been informed).\n",
				irs->sa_len ? irs->sa : " (error)",
				irs->ipsaddr_txt, irs->natt_sport);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}
	}
#endif

	irs->authfuncs=NULL;
	/* authenticate, if required */
#ifdef CONFIG_IPSEC_ALG
	if ((ixt_a=irs->ipsp->ips_alg_auth)) {
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"authalg=%d authlen=%d\n",
				irs->ipsp->ips_authalg, 
				irs->authlen);
	} else
#endif /* CONFIG_IPSEC_ALG */
	switch(irs->ipsp->ips_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
	case AH_MD5:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_md5;
		irs->ictx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
	case AH_SHA:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_sha1;
		irs->ictx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
	case AH_NONE:
		irs->authlen = 0;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;

		break;
	default:
		irs->ipsp->ips_errs.ips_alg_errs += 1;
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADAUTH;
	}

	irs->ilen = irs->len - iphlen - irs->authlen;
	if(irs->ilen <= 0) {
	  KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "runt %s packet with no data, dropping.\n",
		      (proto == IPPROTO_ESP ? "esp" : "ah"));
	  if(irs->stats) {
	    irs->stats->rx_dropped++;
	  }
	  return IPSEC_RCV_BADLEN;
	}

#ifdef CONFIG_IPSEC_ALG
	if(irs->authfuncs || ixt_a) {
#else
	if(irs->authfuncs) {
#endif
		unsigned char *authenticator = NULL;

		if(proto_funcs->setup_auth) {
			enum ipsec_rcv_value retval
			    = (*proto_funcs->setup_auth)(irs, skb,
							 &replay,
							 &authenticator);
			if(retval < 0) {
				return retval;
			}
		}

		if(!authenticator) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_BADAUTH;
		}

		if(!ipsec_checkreplaywindow(irs->ipsp, replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYFAILED;
		}

		/*
		 * verify authenticator
		 */

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "encalg = %d, authalg = %d.\n",
			    irs->ipsp->ips_encalg,
			    irs->ipsp->ips_authalg);

		/* calculate authenticator */
		if(proto_funcs->calc_auth == NULL) {
			return IPSEC_RCV_BADAUTH;
		}
		(*proto_funcs->calc_auth)(irs, skb);

		if (memcmp(irs->hash, authenticator, irs->authlen)) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_INAU,
				    "klips_debug:ipsec_rcv: "
				    "auth failed on incoming packet from %s: hash=%08x%08x%08x auth=%08x%08x%08x, dropped\n",
				    irs->ipsaddr_txt,
				    ntohl(*(__u32*)&irs->hash[0]),
				    ntohl(*(__u32*)&irs->hash[4]),
				    ntohl(*(__u32*)&irs->hash[8]),
				    ntohl(*(__u32*)authenticator),
				    ntohl(*((__u32*)authenticator + 1)),
				    ntohl(*((__u32*)authenticator + 2)));
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_AUTHFAILED;
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "authentication successful.\n");
		}

		/* Crypto hygiene: clear memory used to calculate autheticator.
		 * The length varies with the algorithm.
		 */
		memset(irs->hash, 0, irs->authlen);

		/* If the sequence number == 0, expire SA, it had rolled */
		if(irs->ipsp->ips_replaywin && !replay /* !irs->ipsp->ips_replaywin_lastseq */) {
			ipsec_sa_delchain(irs->ipsp);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "replay window counter rolled, expiring SA.\n");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}

		/* now update the replay counter */
		if (!ipsec_updatereplaywindow(irs->ipsp, replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}
	}

	if(proto_funcs->decrypt) {
		enum ipsec_rcv_value retval =
		  (*proto_funcs->decrypt)(irs);

		if(retval != IPSEC_RCV_OK) {
			return retval;
		}
	}

	/*
	 *	Adjust pointers
	 */
	skb = irs->skb;
	irs->len = skb->len;
	dat = skb->data;

#ifdef NET_21
/*		skb->h.ipiph=(struct iphdr *)skb->data; */
	skb->nh.raw = skb->data;
	skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
	skb->h.iph=(struct iphdr *)skb->data;
	skb->ip_hdr=(struct iphdr *)skb->data;
	memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

	ipp = (struct iphdr *)dat;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));
	/*
	 *	Discard the original ESP/AH header
	 */
	ipp->protocol = irs->next_header;

	ipp->check = 0;	/* NOTE: this will be included in checksum */
	ipp->check = ip_fast_csum((unsigned char *)dat, iphlen >> 2);

	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(irs->ipsp),
		    irs->sa_len ? irs->sa : " (error)");
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = 0;

	ipsnext = irs->ipsp->ips_inext;
	if(sysctl_ipsec_inbound_policy_check) {
		if(ipsnext) {
			if(
				ipp->protocol != IPPROTO_AH
				&& ipp->protocol != IPPROTO_ESP
#ifdef CONFIG_IPSEC_IPCOMP
				&& ipp->protocol != IPPROTO_COMP
				&& (ipsnext->ips_said.proto != IPPROTO_COMP
				    || ipsnext->ips_inext)
#endif /* CONFIG_IPSEC_IPCOMP */
				&& ipp->protocol != IPPROTO_IPIP
				) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "packet with incomplete policy dropped, last successful SA:%s.\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Another IPSEC header to process.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "No ips_inext from this SA:%s.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}
	}

#ifdef CONFIG_IPSEC_IPCOMP
	/* update ipcomp ratio counters, even if no ipcomp packet is present */
	if (ipsnext
	    && ipsnext->ips_said.proto == IPPROTO_COMP
	    && ipp->protocol != IPPROTO_COMP) {
		ipsnext->ips_comp_ratio_cbytes += ntohs(ipp->tot_len);
		ipsnext->ips_comp_ratio_dbytes += ntohs(ipp->tot_len);
	}
#endif /* CONFIG_IPSEC_IPCOMP */

	irs->ipsp->ips_life.ipl_bytes.ipl_count += irs->len;
	irs->ipsp->ips_life.ipl_bytes.ipl_last   = irs->len;

	if(!irs->ipsp->ips_life.ipl_usetime.ipl_count) {
		irs->ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
	}
	irs->ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
	irs->ipsp->ips_life.ipl_packets.ipl_count += 1;

#ifdef CONFIG_NETFILTER
	if(proto == IPPROTO_ESP || proto == IPPROTO_AH) {
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(irs->ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "%s SA sets skb->nfmark=0x%x.\n",
			    proto == IPPROTO_ESP ? "ESP" : "AH",
			    (unsigned)skb->nfmark);
	}
#endif /* CONFIG_NETFILTER */

	return IPSEC_RCV_OK;
}


int
#ifdef PROTO_HANDLER_SINGLE_PARM
ipsec_rcv(struct sk_buff *skb)
#else /* PROTO_HANDLER_SINGLE_PARM */
#ifdef NET_21
ipsec_rcv(struct sk_buff *skb, unsigned short xlen)
#else /* NET_21 */
ipsec_rcv(struct sk_buff *skb, struct device *dev, struct options *opt,
		__u32 daddr_unused, unsigned short xlen, __u32 saddr,
				   int redo, struct inet_protocol *protocol)
#endif /* NET_21 */
#endif /* PROTO_HANDLER_SINGLE_PARM */
{
#ifdef NET_21
#ifdef CONFIG_IPSEC_DEBUG
	struct device *dev = skb->dev;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* NET_21 */
	unsigned char protoc;
	struct iphdr *ipp;
#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */

	struct ipsec_sa *ipsp = NULL;
	struct net_device_stats *stats = NULL;		/* This device's statistics */
	struct device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	char name[9];
	int i;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;

	struct ipsec_sa* ipsnext = NULL;	/* next SA towards inside of packet */
	struct ipsec_rcv_state irs;

	/* Don't unlink in the middle of a turnaround */
	MOD_INC_USE_COUNT;

	memset(&irs, 0, sizeof(struct ipsec_rcv_state));

	if (skb == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto rcvleave;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto rcvleave;
	}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (skb->sk && skb->nh.iph && skb->nh.iph->protocol==IPPROTO_UDP) {
		/**
		 * Packet comes from udp_queue_rcv_skb so it is already defrag,
		 * checksum verified, ... (ie safe to use)
		 *
		 * If the packet is not for us, return -1 and udp_queue_rcv_skb
		 * will continue to handle it (do not kfree skb !!).
		 */
		struct udp_opt *tp =  &(skb->sk->tp_pinfo.af_udp);
		struct iphdr *ip = (struct iphdr *)skb->nh.iph;
		struct udphdr *udp = (struct udphdr *)((__u32 *)ip+ip->ihl);
		__u8 *udpdata = (__u8 *)udp + sizeof(struct udphdr);
		__u32 *udpdata32 = (__u32 *)udpdata;

		irs.natt_sport = ntohs(udp->source);
		irs.natt_dport = ntohs(udp->dest);

		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "suspected ESPinUDP packet (NAT-Traversal) [%d].\n",
			tp->esp_in_udp);
		KLIPS_IP_PRINT(debug_rcv, ip);

		if (udpdata < skb->tail) {
			unsigned int len = skb->tail - udpdata;
			if ((len==1) && (udpdata[0]==0xff)) {
				KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
					/* not IPv6 compliant message */
				    "NAT-keepalive from %d.%d.%d.%d.\n", NIPQUAD(ip->saddr));
				goto rcvleave;
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_IKE) &&
				(len > (2*sizeof(__u32) + sizeof(struct esphdr))) &&
				(udpdata32[0]==0) && (udpdata32[1]==0) ) {
				/* ESP Packet with Non-IKE header */
				KLIPS_PRINT(debug_rcv, 
					"klips_debug:ipsec_rcv: "
					"ESPinUDP pkt with Non-IKE - spi=0x%x\n",
					udpdata32[2]);
				irs.natt_type = ESPINUDP_WITH_NON_IKE;
				irs.natt_len = sizeof(struct udphdr)+(2*sizeof(__u32));
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_ESP) &&
				(len > sizeof(struct esphdr)) &&
				(udpdata32[0]!=0) ) {
				/* ESP Packet without Non-ESP header */
				irs.natt_type = ESPINUDP_WITH_NON_ESP;
				irs.natt_len = sizeof(struct udphdr);
				KLIPS_PRINT(debug_rcv, 
					"klips_debug:ipsec_rcv: "
					"ESPinUDP pkt without Non-ESP - spi=0x%x\n",
					udpdata32[0]);
			}
			else {
				KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
					"IKE packet - not handled here\n");
				MOD_DEC_USE_COUNT;
				return -1;
			}
		}
		else {
			MOD_DEC_USE_COUNT;
			return -1;
		}
	}
#endif

#ifdef IPH_is_SKB_PULLED
	/* In Linux 2.4.4, the IP header has been skb_pull()ed before the
	   packet is passed to us. So we'll skb_push() to get back to it. */
	if (skb->data == skb->h.raw) {
		skb_push(skb, skb->h.raw - skb->nh.raw);
	}
#endif /* IPH_is_SKB_PULLED */

	/* dev->hard_header_len is unreliable and should not be used */
	irs.hard_header_len = skb->mac.raw ? (skb->data - skb->mac.raw) : 0;
	if((irs.hard_header_len < 0) || (irs.hard_header_len > skb_headroom(skb)))
		irs.hard_header_len = 0;

#ifdef NET_21
	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if(skb_cloned(skb)) {
		/* include any mac header while copying.. */
		if(skb_headroom(skb) < irs.hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs.hard_header_len,
			       skb_headroom(skb));
			goto rcvleave;
		}
		skb_push(skb, irs.hard_header_len);
		if
#ifdef SKB_COW_NEW
		  (skb_cow(skb, skb_headroom(skb)) != 0)
#else /* SKB_COW_NEW */
		  ((skb = skb_cow(skb, skb_headroom(skb))) == NULL)
#endif /* SKB_COW_NEW */
		{
			goto rcvleave;
		}
		if(skb->len < irs.hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs.hard_header_len,
			       skb->len);
			goto rcvleave;
		}
		skb_pull(skb, irs.hard_header_len);
	}

#endif /* NET_21 */

#if IP_FRAGMENT_LINEARIZE
	/* In Linux 2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	*/
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb, GFP_ATOMIC) != 0) {
			goto rcvleave;
		}
	}
#endif /* IP_FRAGMENT_LINEARIZE */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (irs.natt_len) {
		/**
		 * Now, we are sure packet is ESPinUDP. Remove natt_len bytes from
		 * packet and modify protocol to ESP.
		 */
		if (((unsigned char *)skb->data > (unsigned char *)skb->nh.iph) &&
			((unsigned char *)skb->nh.iph > (unsigned char *)skb->head)) {
			unsigned int _len = (unsigned char *)skb->data -
				(unsigned char *)skb->nh.iph;
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: adjusting skb: skb_push(%u)\n",
				_len);
			skb_push(skb, _len);
		}
		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
			"removing %d bytes from ESPinUDP packet\n", irs.natt_len);
		ipp = (struct iphdr *)skb->data;
		irs.iphlen = ipp->ihl << 2;
		ipp->tot_len = htons(ntohs(ipp->tot_len) - irs.natt_len);
		if (skb->len < irs.iphlen + irs.natt_len) {
			printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "ESPinUDP packet is too small (%d < %d+%d). "
			   "This should never happen, please report.\n",
		       (int)(skb->len), irs.iphlen, irs.natt_len);
			goto rcvleave;
		}
		memmove(skb->data + irs.natt_len, skb->data, irs.iphlen);
		skb_pull(skb, irs.natt_len);

		/* update nh.iph */
		ipp = skb->nh.iph = (struct iphdr *)skb->data;

		/* modify protocol */
		ipp->protocol = IPPROTO_ESP;

		skb->sk = NULL;

		KLIPS_IP_PRINT(debug_rcv, skb->nh.iph);
	}
#endif

	ipp = skb->nh.iph;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs.ipsaddr_txt, sizeof(irs.ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs.ipdaddr_txt, sizeof(irs.ipdaddr_txt));
	irs.iphlen = ipp->ihl << 2;

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "<<< Info -- ");
	KLIPS_PRINTMORE(debug_rcv && skb->dev, "skb->dev=%s ",
			skb->dev->name ? skb->dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv && dev, "dev=%s ",
			dev->name ? dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv, "\n");

	KLIPS_PRINT(debug_rcv && !(skb->dev && dev && (skb->dev == dev)),
		    "klips_debug:ipsec_rcv: "
		    "Informational -- **if this happens, find out why** skb->dev:%s is not equal to dev:%s\n",
		    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL",
		    dev ? (dev->name ? dev->name : "NULL") : "NULL");

	protoc = ipp->protocol;
#ifndef NET_21
	if((!protocol) || (protocol->protocol != protoc)) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: "
			    "protocol arg is NULL or unequal to the packet contents, this is odd, using value in packet.\n");
	}
#endif /* !NET_21 */

	if( (protoc != IPPROTO_AH) &&
#ifdef CONFIG_IPSEC_IPCOMP_disabled_until_we_register_IPCOMP_HANDLER
	    (protoc != IPPROTO_COMP) &&
#endif /* CONFIG_IPSEC_IPCOMP */
	    (protoc != IPPROTO_ESP) ) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: Why the hell is someone "
			    "passing me a non-ipsec protocol = %d packet? -- dropped.\n",
			    protoc);
		goto rcvleave;
	}

	if(skb->dev) {
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, IPSEC_DEV_FORMAT, i);
			if(!strcmp(name, skb->dev->name)) {
				prv = (struct ipsecpriv *)(skb->dev->priv);
				if(prv) {
					stats = (struct net_device_stats *) &(prv->mystats);
				}
				ipsecdev = skb->dev;
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "Info -- pkt already proc'ed a group of ipsec headers, processing next group of ipsec headers.\n");
				break;
			}
			if((ipsecdev = __ipsec_dev_get(name)) == NULL) {
				KLIPS_PRINT(debug_rcv,
					    "klips_error:ipsec_rcv: "
					    "device %s does not exist\n",
					    name);
			}
			prv = ipsecdev ? (struct ipsecpriv *)(ipsecdev->priv) : NULL;
			prvdev = prv ? (struct device *)(prv->dev) : NULL;

#if 0
			KLIPS_PRINT(debug_rcv && prvdev,
				    "klips_debug:ipsec_rcv: "
				    "physical device for device %s is %s\n",
				    name,
				    prvdev->name);
#endif
			if(prvdev && skb->dev &&
			   !strcmp(prvdev->name, skb->dev->name)) {
				stats = prv ? ((struct net_device_stats *) &(prv->mystats)) : NULL;
				skb->dev = ipsecdev;
				KLIPS_PRINT(debug_rcv && prvdev,
					    "klips_debug:ipsec_rcv: "
					    "assigning packet ownership to virtual device %s from physical device %s.\n",
					    name, prvdev->name);
				if(stats) {
					stats->rx_packets++;
				}
				break;
			}
		}
	} else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "device supplied with skb is NULL\n");
	}

	if(stats == NULL) {
		KLIPS_PRINT((debug_rcv),
			    "klips_error:ipsec_rcv: "
			    "packet received from physical I/F (%s) not connected to ipsec I/F.  Cannot record stats.  May not have SA for decoding.  Is IPSEC traffic expected on this I/F?  Check routing.\n",
			    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL");
	}
		
	KLIPS_IP_PRINT(debug_rcv, ipp);

	/* begin decapsulating loop here */

	/*
	  The spinlock is to prevent any other process from
	  accessing or deleting the ipsec_sa hash table or any of the
	  ipsec_sa s while we are using and updating them.

	  This is not optimal, but was relatively straightforward
	  at the time.  A better way to do it has been planned for
	  more than a year, to lock the hash table and put reference
	  counts on each ipsec_sa instead.  This is not likely to happen
	  in KLIPS1 unless a volunteer contributes it, but will be
	  designed into KLIPS2.
	*/
	spin_lock(&tdb_lock);

	/* set up for decap loop */
	irs.stats= stats;
	irs.ipp  = ipp;
	irs.ipsp = NULL;
	irs.ilen = 0;
	irs.authlen=0;
	irs.authfuncs=NULL;
	irs.skb = skb;

	do {
	        int decap_stat;

	        decap_stat = ipsec_rcv_decap_once(&irs);

		if(decap_stat != IPSEC_RCV_OK) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: decap_once failed: %d\n",
				    decap_stat);
		
			goto rcvleave;
		}
	/* end decapsulation loop here */
	} while(   (irs.ipp->protocol == IPPROTO_ESP )
		|| (irs.ipp->protocol == IPPROTO_AH  )
#ifdef CONFIG_IPSEC_IPCOMP
		|| (irs.ipp->protocol == IPPROTO_COMP)
#endif /* CONFIG_IPSEC_IPCOMP */
		);

	/* set up for decap loop */
	ipp  =irs.ipp;
	ipsp =irs.ipsp;
	ipsnext = ipsp->ips_inext;
	skb = irs.skb;

	/* if there is an IPCOMP, but we don't have an IPPROTO_COMP,
	 * then we can just skip it
	 */
#ifdef CONFIG_IPSEC_IPCOMP
	if(ipsnext && ipsnext->ips_said.proto == IPPROTO_COMP) {
		ipsp = ipsnext;
		ipsnext = ipsp->ips_inext;
	}
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((irs.natt_type) && (ipp->protocol != IPPROTO_IPIP)) {
		/**
		 * NAT-Traversal and Transport Mode:
		 *   we need to correct TCP/UDP checksum
		 *
		 * If we've got NAT-OA, we can fix checksum without recalculation.
		 */
		__u32 natt_oa = ipsp->ips_natt_oa ?
			((struct sockaddr_in*)(ipsp->ips_natt_oa))->sin_addr.s_addr : 0;
		__u16 pkt_len = skb->tail - (unsigned char *)ipp;
		__u16 data_len = pkt_len - (ipp->ihl << 2);

		switch (ipp->protocol) {
			case IPPROTO_TCP:
				if (data_len >= sizeof(struct tcphdr)) {
					struct tcphdr *tcp = (struct tcphdr *)((__u32 *)ipp+ipp->ihl);
					if (natt_oa) {
						__u32 buff[2] = { ~natt_oa, ipp->saddr };
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: "
							"fix TCP checksum using NAT-OA\n");
						tcp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							tcp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_rcv,
			    			"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: recalc TCP checksum\n");
						if (pkt_len > (ntohs(ipp->tot_len)))
							data_len -= (pkt_len - ntohs(ipp->tot_len));
						tcp->check = 0;
						tcp->check = csum_tcpudp_magic(ipp->saddr, ipp->daddr,
							data_len, IPPROTO_TCP,
							csum_partial((unsigned char *)tcp, data_len, 0));
					}
				}
				else {
					KLIPS_PRINT(debug_rcv,
			    		"klips_debug:ipsec_rcv: "
						"NAT-T & TRANSPORT: can't fix TCP checksum\n");
				}
				break;
			case IPPROTO_UDP:
				if (data_len >= sizeof(struct udphdr)) {
					struct udphdr *udp = (struct udphdr *)((__u32 *)ipp+ipp->ihl);
					if (udp->check == 0) {
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: UDP checksum already 0\n");
					}
					else if (natt_oa) {
						__u32 buff[2] = { ~natt_oa, ipp->saddr };
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: "
							"fix UDP checksum using NAT-OA\n");
						udp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							udp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: zero UDP checksum\n");
						udp->check = 0;
					}
				}
				else {
					KLIPS_PRINT(debug_rcv,
			    		"klips_debug:ipsec_rcv: "
						"NAT-T & TRANSPORT: can't fix UDP checksum\n");
				}
				break;
			default:
				KLIPS_PRINT(debug_rcv,
			    	"klips_debug:ipsec_rcv: "
					"NAT-T & TRANSPORT: non TCP/UDP packet -- do nothing\n");
				break;
		}
	}
#endif

	/*
	 * XXX this needs to be locked from when it was first looked
	 * up in the decapsulation loop.  Perhaps it is better to put
	 * the IPIP decap inside the loop.
	 */
	if(ipsnext) {
		ipsp = ipsnext;
		irs.sa_len = satoa(irs.said, 0, irs.sa, SATOA_BUF);
		if(ipp->protocol != IPPROTO_IPIP) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Hey!  How did this get through?  Dropped.\n",
				    irs.sa_len ? irs.sa : " (error)");
			if(stats) {
				stats->rx_dropped++;
			}
			goto rcvleave;
		}
		if(sysctl_ipsec_inbound_policy_check) {
			if((ipsnext = ipsp->ips_inext)) {
				char sa2[SATOA_BUF];
				size_t sa_len2;
				sa_len2 = satoa(ipsnext->ips_said, 0, sa2, SATOA_BUF);
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s after IPIP SA:%s\n",
					    sa_len2 ? sa2 : " (error)",
					    irs.sa_len ? irs.sa : " (error)");
				if(stats) {
					stats->rx_dropped++;
				}
				goto rcvleave;
			}
			if(ipp->saddr != ((struct sockaddr_in*)(ipsp->ips_addr_s))->sin_addr.s_addr) {
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
					    irs.sa_len ? irs.sa : " (error)",
					    irs.ipsaddr_txt);
				if(stats) {
					stats->rx_dropped++;
				}
				goto rcvleave;
			}
		}

		/*
		 * XXX this needs to be locked from when it was first looked
		 * up in the decapsulation loop.  Perhaps it is better to put
		 * the IPIP decap inside the loop.
		 */
		ipsp->ips_life.ipl_bytes.ipl_count += skb->len;
		ipsp->ips_life.ipl_bytes.ipl_last   = skb->len;

		if(!ipsp->ips_life.ipl_usetime.ipl_count) {
			ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
		}
		ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
		ipsp->ips_life.ipl_packets.ipl_count += 1;

		if(skb->len < irs.iphlen) {
			spin_unlock(&tdb_lock);
			printk(KERN_WARNING "klips_debug:ipsec_rcv: "
			       "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report.\n",
			       irs.iphlen,
			       (int)(skb->len));

			goto rcvleave;
		}
		skb_pull(skb, irs.iphlen);

#ifdef NET_21
		skb->nh.raw = skb->data;
		ipp = (struct iphdr *)skb->nh.raw;
		skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
		ipp = skb->ip_hdr = skb->h.iph = (struct iphdr *)skb->data;

		memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */
		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs.ipsaddr_txt, sizeof(irs.ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs.ipdaddr_txt, sizeof(irs.ipdaddr_txt));

		skb->protocol = htons(ETH_P_IP);
		skb->ip_summed = 0;
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP tunnel stripped.\n");
		KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

		if(sysctl_ipsec_inbound_policy_check
		   /*
		      Note: "xor" (^) logically replaces "not equal"
		      (!=) and "bitwise or" (|) logically replaces
		      "boolean or" (||).  This is done to speed up
		      execution by doing only bitwise operations and
		      no branch operations
		   */
		   && (((ipp->saddr & ipsp->ips_mask_s.u.v4.sin_addr.s_addr)
				    ^ ipsp->ips_flow_s.u.v4.sin_addr.s_addr)
		       | ((ipp->daddr & ipsp->ips_mask_d.u.v4.sin_addr.s_addr)
				      ^ ipsp->ips_flow_d.u.v4.sin_addr.s_addr)) )
		{
			char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

			subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
				ipsp->ips_mask_s.u.v4.sin_addr,
				0, sflow_txt, sizeof(sflow_txt));
			subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
				ipsp->ips_mask_d.u.v4.sin_addr,
				0, dflow_txt, sizeof(dflow_txt));
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
				    irs.sa_len ? irs.sa : " (error)",
				    sflow_txt,
				    dflow_txt,
				    irs.ipsaddr_txt,
				    irs.ipdaddr_txt);
			if(stats) {
				stats->rx_dropped++;
			}
			goto rcvleave;
		}
#ifdef CONFIG_NETFILTER
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_TABLE_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP SA sets skb->nfmark=0x%x.\n",
			    (unsigned)skb->nfmark);
#endif /* CONFIG_NETFILTER */
	}

	spin_unlock(&tdb_lock);

#ifdef NET_21
	if(stats) {
		stats->rx_bytes += skb->len;
	}
	if(skb->dst) {
		dst_release(skb->dst);
		skb->dst = NULL;
	}
	skb->pkt_type = PACKET_HOST;
	if(irs.hard_header_len &&
	   (skb->mac.raw != (skb->data - irs.hard_header_len)) &&
	   (irs.hard_header_len <= skb_headroom(skb))) {
		/* copy back original MAC header */
		memmove(skb->data - irs.hard_header_len, skb->mac.raw, irs.hard_header_len);
		skb->mac.raw = skb->data - irs.hard_header_len;
	}
#endif /* NET_21 */

#ifdef CONFIG_IPSEC_IPCOMP
	if(ipp->protocol == IPPROTO_COMP) {
		unsigned int flags = 0;

		if(sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"inbound policy checking enabled, IPCOMP follows IPIP, dropped.\n");
			if (stats) {
				stats->rx_errors++;
			}
			goto rcvleave;
		}
		/*
		  XXX need a ipsec_sa for updating ratio counters but it is not
		  following policy anyways so it is not a priority
		*/
		skb = skb_decompress(skb, NULL, &flags);
		if (!skb || flags) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"skb_decompress() returned error flags: %d, dropped.\n",
				flags);
			if (stats) {
				stats->rx_errors++;
			}
			goto rcvleave;
		}
	}
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef SKB_RESET_NFCT
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* SKB_RESET_NFCT */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "netif_rx() called.\n");
	netif_rx(skb);

	MOD_DEC_USE_COUNT;
	return(0);

 rcvleave:
	if(skb) {
		ipsec_kfree_skb(skb);
	}

	MOD_DEC_USE_COUNT;
	return(0);
}

struct inet_protocol ah_protocol =
{
	ipsec_rcv,				/* AH handler */
	NULL,				/* TUNNEL error control */
#ifdef NETDEV_25
	1,				/* no policy */
#else
	0,				/* next */
	IPPROTO_AH,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"AH"				/* name */
#endif
};

struct inet_protocol esp_protocol =
{
	ipsec_rcv,			/* ESP handler		*/
	NULL,				/* TUNNEL error control */
#ifdef NETDEV_25
	1,				/* no policy */
#else
	0,				/* next */
	IPPROTO_ESP,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"ESP"				/* name */
#endif
};

#if 0
/* We probably don't want to install a pure IPCOMP protocol handler, but
   only want to handle IPCOMP if it is encapsulated inside an ESP payload
   (which is already handled) */
#ifdef CONFIG_IPSEC_IPCOMP
struct inet_protocol comp_protocol =
{
	ipsec_rcv,			/* COMP handler		*/
	NULL,				/* COMP error control	*/
#ifdef NETDEV_25
	1,				/* no policy */
#else
	0,				/* next */
	IPPROTO_COMP,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"COMP"				/* name */
#endif
};
#endif /* CONFIG_IPSEC_IPCOMP */
#endif
