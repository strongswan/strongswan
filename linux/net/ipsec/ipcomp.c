/*
 * IPCOMP zlib interface code.
 * Copyright (C) 2000  Svenning Soerensen <svenning@post5.tele.dk>
 * Copyright (C) 2000, 2001  Richard Guy Briggs <rgb@conscoop.ottawa.on.ca>
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

char ipcomp_c_version[] = "RCSID $Id: ipcomp.c,v 1.2 2004/06/13 19:57:49 as Exp $";

/* SSS */

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
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/skbuff.h>

#include <freeswan.h>

#ifdef NET_21
# include <net/dst.h>
# include <asm/uaccess.h>
# include <linux/in6.h>
# define proto_priv cb
#endif /* NET21 */
#include <asm/checksum.h>
#include <net/ip.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_sa.h"

#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_tunnel.h"
#include "freeswan/ipsec_rcv.h" /* sysctl_ipsec_inbound_policy_check */
#include "freeswan/ipcomp.h"
#include "zlib/zlib.h"
#include "zlib/zutil.h"

#include <pfkeyv2.h> /* SADB_X_CALG_DEFLATE */

#ifdef CONFIG_IPSEC_DEBUG
int sysctl_ipsec_debug_ipcomp = 0;
#endif /* CONFIG_IPSEC_DEBUG */

static
struct sk_buff *skb_copy_ipcomp(struct sk_buff *skb, int data_growth, int gfp_mask);

static
voidpf my_zcalloc(voidpf opaque, uInt items, uInt size)
{
	return (voidpf) kmalloc(items*size, GFP_ATOMIC);
}

static
void my_zfree(voidpf opaque, voidpf address)
{
	kfree(address);
}

struct sk_buff *skb_compress(struct sk_buff *skb, struct ipsec_sa *ips, unsigned int *flags)
{
	struct iphdr *iph;
	unsigned int iphlen, pyldsz, cpyldsz;
	unsigned char *buffer;
	z_stream zs;
	int zresult;
	
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_compress: .\n");

	if(skb == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "passed in NULL skb, returning ERROR.\n");
		if(flags != NULL) {
			*flags |= IPCOMP_PARMERROR;
		}
		return skb;
	}

	if(ips == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "passed in NULL ipsec_sa needed for cpi, returning ERROR.\n");
		if(flags) {
			*flags |= IPCOMP_PARMERROR;
		}
		return skb;
	}

	if (flags == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "passed in NULL flags, returning ERROR.\n");
		ipsec_kfree_skb(skb);
		return NULL;
	}
	
#ifdef NET_21
	iph = skb->nh.iph;
#else /* NET_21 */
	iph = skb->ip_hdr;
#endif /* NET_21 */

	switch (iph->protocol) {
	case IPPROTO_COMP:
	case IPPROTO_AH:
	case IPPROTO_ESP:
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression of packet with ip protocol %d.\n",
			    iph->protocol);
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}
	
	/* Don't compress packets already fragmented */
	if (iph->frag_off & __constant_htons(IP_MF | IP_OFFSET)) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression of fragmented packet.\n");
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}
	
	iphlen = iph->ihl << 2;
	pyldsz = ntohs(iph->tot_len) - iphlen;

	/* Don't compress less than 90 bytes (rfc 2394) */
	if (pyldsz < 90) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression of tiny packet, len=%d.\n",
			    pyldsz);
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}
	
	/* Adaptive decision */
	if (ips->ips_comp_adapt_skip) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression: ips_comp_adapt_skip=%d.\n",
			    ips->ips_comp_adapt_skip);
		ips->ips_comp_adapt_skip--;
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}

	zs.zalloc = my_zcalloc;
	zs.zfree = my_zfree;
	zs.opaque = 0;
	
	/* We want to use deflateInit2 because we don't want the adler
	   header. */
	zresult = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -11,
			       DEF_MEM_LEVEL,  Z_DEFAULT_STRATEGY);
	if (zresult != Z_OK) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_compress: "
			    "deflateInit2() returned error %d (%s), "
			    "skipping compression.\n",
			    zresult,
			    zs.msg ? zs.msg : zError(zresult));
		*flags |= IPCOMP_COMPRESSIONERROR;
		return skb;
	}
	

	/* Max output size. Result should be max this size.
	 * Implementation specific tweak:
	 * If it's not at least 32 bytes and 6.25% smaller than
	 * the original packet, it's probably not worth wasting
	 * the receiver's CPU cycles decompressing it.
	 * Your mileage may vary.
	 */
	cpyldsz = pyldsz - sizeof(struct ipcomphdr) - (pyldsz <= 512 ? 32 : pyldsz >> 4);

	buffer = kmalloc(cpyldsz, GFP_ATOMIC);
	if (!buffer) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_compress: "
			    "unable to kmalloc(%d, GFP_ATOMIC), "
			    "skipping compression.\n",
			    cpyldsz);
		*flags |= IPCOMP_COMPRESSIONERROR;
		deflateEnd(&zs);
		return skb;
	}
	
#ifdef CONFIG_IPSEC_DEBUG
	if(sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int i;

		c = (__u8*)iph + iphlen;
		for(i = 0; i < pyldsz; i++, c++) {
			if(!(i % 16)) {
				printk(KERN_INFO "skb_compress:   before:");
			}
			printk("%02x ", *c);
			if(!((i + 1) % 16)) {
				printk("\n");
			}
		}
		if(i % 16) {
			printk("\n");
		}
	}
#endif /* CONFIG_IPSEC_DEBUG */

	zs.next_in = (char *) iph + iphlen; /* start of payload */
	zs.avail_in = pyldsz;
	zs.next_out = buffer;     /* start of compressed payload */
	zs.avail_out = cpyldsz;
	
	/* Finish compression in one step */
	zresult = deflate(&zs, Z_FINISH);

	/* Free all dynamically allocated buffers */
	deflateEnd(&zs);
	if (zresult != Z_STREAM_END) {
		*flags |= IPCOMP_UNCOMPRESSABLE;
		kfree(buffer);

		/* Adjust adaptive counters */
		if (++(ips->ips_comp_adapt_tries) == IPCOMP_ADAPT_INITIAL_TRIES) {
			KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
				    "klips_debug:skb_compress: "
				    "first %d packets didn't compress, "
				    "skipping next %d\n",
				    IPCOMP_ADAPT_INITIAL_TRIES,
				    IPCOMP_ADAPT_INITIAL_SKIP);
			ips->ips_comp_adapt_skip = IPCOMP_ADAPT_INITIAL_SKIP;
		}
		else if (ips->ips_comp_adapt_tries == IPCOMP_ADAPT_INITIAL_TRIES + IPCOMP_ADAPT_SUBSEQ_TRIES) {
			KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
				    "klips_debug:skb_compress: "
				    "next %d packets didn't compress, "
				    "skipping next %d\n",
				    IPCOMP_ADAPT_SUBSEQ_TRIES,
				    IPCOMP_ADAPT_SUBSEQ_SKIP);
			ips->ips_comp_adapt_skip = IPCOMP_ADAPT_SUBSEQ_SKIP;
			ips->ips_comp_adapt_tries = IPCOMP_ADAPT_INITIAL_TRIES;
		}

		return skb;
	}
	
	/* resulting compressed size */
	cpyldsz -= zs.avail_out;
	
	/* Insert IPCOMP header */
	((struct ipcomphdr*) ((char*) iph + iphlen))->ipcomp_nh = iph->protocol;
	((struct ipcomphdr*) ((char*) iph + iphlen))->ipcomp_flags = 0;
	/* use the bottom 16 bits of the spi for the cpi.  The top 16 bits are
	   for internal reference only. */
	((struct ipcomphdr*) (((char*)iph) + iphlen))->ipcomp_cpi = htons((__u16)(ntohl(ips->ips_said.spi) & 0x0000ffff));
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_compress: "
		    "spi=%08x, spi&0xffff=%04x, cpi=%04x, payload size: raw=%d, comp=%d.\n",
		    ntohl(ips->ips_said.spi),
		    ntohl(ips->ips_said.spi) & 0x0000ffff,
		    ntohs(((struct ipcomphdr*)(((char*)iph)+iphlen))->ipcomp_cpi),
		    pyldsz,
		    cpyldsz);
	
	/* Update IP header */
	iph->protocol = IPPROTO_COMP;
	iph->tot_len = htons(iphlen + sizeof(struct ipcomphdr) + cpyldsz);
#if 1 /* XXX checksum is done by ipsec_tunnel ? */
	iph->check = 0;
	iph->check = ip_fast_csum((char *) iph, iph->ihl);
#endif
	
	/* Copy compressed payload */
	memcpy((char *) iph + iphlen + sizeof(struct ipcomphdr),
	       buffer,
	       cpyldsz);
	kfree(buffer);
	
	/* Update skb length/tail by "unputting" the shrinkage */
	skb_put(skb,
		cpyldsz + sizeof(struct ipcomphdr) - pyldsz);
	
#ifdef CONFIG_IPSEC_DEBUG
	if(sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int i;
		
		c = (__u8*)iph + iphlen + sizeof(struct ipcomphdr);
		for(i = 0; i < cpyldsz; i++, c++) {
			if(!(i % 16)) {
				printk(KERN_INFO "skb_compress:   result:");
			}
			printk("%02x ", *c);
			if(!((i + 1) % 16)) {
				printk("\n");
			}
		}
		if(i % 16) {
			printk("\n");
		}
	}
#endif /* CONFIG_IPSEC_DEBUG */
	
	ips->ips_comp_adapt_skip = 0;
	ips->ips_comp_adapt_tries = 0;
	
	return skb;
}

struct sk_buff *skb_decompress(struct sk_buff *skb, struct ipsec_sa *ips, unsigned int *flags)
{
	struct sk_buff *nskb = NULL;

	/* original ip header */
	struct iphdr *oiph, *iph;
	unsigned int iphlen, pyldsz, cpyldsz;
	z_stream zs;
	int zresult;

	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_decompress: .\n");

	if(!skb) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "passed in NULL skb, returning ERROR.\n");
		if (flags) *flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if(!ips && sysctl_ipsec_inbound_policy_check) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "passed in NULL ipsec_sa needed for comp alg, returning ERROR.\n");
		if (flags) *flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if (!flags) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "passed in NULL flags, returning ERROR.\n");
		ipsec_kfree_skb(skb);
		return NULL;
	}
	
#ifdef NET_21
	oiph = skb->nh.iph;
#else /* NET_21 */
	oiph = skb->ip_hdr;
#endif /* NET_21 */
	
	iphlen = oiph->ihl << 2;
	
	if (oiph->protocol != IPPROTO_COMP) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "called with non-IPCOMP packet (protocol=%d),"
			    "skipping decompression.\n",
			    oiph->protocol);
		*flags |= IPCOMP_PARMERROR;
		return skb;
	}
	
	if ( (((struct ipcomphdr*)((char*) oiph + iphlen))->ipcomp_flags != 0)
	     || ((((struct ipcomphdr*) ((char*) oiph + iphlen))->ipcomp_cpi
		!= htons(SADB_X_CALG_DEFLATE))
		 && sysctl_ipsec_inbound_policy_check
		 && (!ips || (ips && (ips->ips_encalg != SADB_X_CALG_DEFLATE)))) ) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "called with incompatible IPCOMP packet (flags=%d, "
			    "cpi=%d), ips-compalg=%d, skipping decompression.\n",
			    ntohs(((struct ipcomphdr*) ((char*) oiph + iphlen))->ipcomp_flags),
			    ntohs(((struct ipcomphdr*) ((char*) oiph + iphlen))->ipcomp_cpi),
			    ips ? ips->ips_encalg : 0);
		*flags |= IPCOMP_PARMERROR;
		
		return skb;
	}
	
	if (ntohs(oiph->frag_off) & ~0x4000) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "called with fragmented IPCOMP packet, "
			    "skipping decompression.\n");
		*flags |= IPCOMP_PARMERROR;
		return skb;
	}
	
	/* original compressed payload size */
	cpyldsz = ntohs(oiph->tot_len) - iphlen - sizeof(struct ipcomphdr);

	zs.zalloc = my_zcalloc;
	zs.zfree = my_zfree;
	zs.opaque = 0;
	
	zs.next_in = (char *) oiph + iphlen + sizeof(struct ipcomphdr);
	zs.avail_in = cpyldsz;
	
	/* Maybe we should be a bit conservative about memory
	   requirements and use inflateInit2 */
	/* Beware, that this might make us unable to decompress packets
	   from other implementations - HINT: check PGPnet source code */
	/* We want to use inflateInit2 because we don't want the adler
	   header. */
	zresult = inflateInit2(&zs, -15); 
	if (zresult != Z_OK) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "inflateInit2() returned error %d (%s), "
			    "skipping decompression.\n",
			    zresult,
			    zs.msg ? zs.msg : zError(zresult));
		*flags |= IPCOMP_DECOMPRESSIONERROR;

		return skb;
	}
	
	/* We have no way of knowing the exact length of the resulting
	   decompressed output before we have actually done the decompression.
	   For now, we guess that the packet will not be bigger than the
	   attached ipsec device's mtu or 16260, whichever is biggest.
	   This may be wrong, since the sender's mtu may be bigger yet.
	   XXX This must be dealt with later XXX
	*/
	
	/* max payload size */
	pyldsz = skb->dev ? (skb->dev->mtu < 16260 ? 16260 : skb->dev->mtu)
			  : (65520 - iphlen);
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_decompress: "
		    "max payload size: %d\n", pyldsz);
	
	while (pyldsz > (cpyldsz + sizeof(struct ipcomphdr)) && 
	       (nskb = skb_copy_ipcomp(skb,
				       pyldsz - cpyldsz - sizeof(struct ipcomphdr),
				       GFP_ATOMIC)) == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "unable to skb_copy_ipcomp(skb, %d, GFP_ATOMIC), "
			    "trying with less payload size.\n",
			    (int)(pyldsz - cpyldsz - sizeof(struct ipcomphdr)));
		pyldsz >>=1;
	}
	
	if (!nskb) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "unable to allocate memory, dropping packet.\n");
		*flags |= IPCOMP_DECOMPRESSIONERROR;
		inflateEnd(&zs);

		return skb;
	}
	
#ifdef CONFIG_IPSEC_DEBUG
	if(sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int i;
		
		c = (__u8*)oiph + iphlen + sizeof(struct ipcomphdr);
		for(i = 0; i < cpyldsz; i++, c++) {
			if(!(i % 16)) {
				printk(KERN_INFO "skb_decompress:   before:");
			}
			printk("%02x ", *c);
			if(!((i + 1) % 16)) {
				printk("\n");
			}
		}
		if(i % 16) {
			printk("\n");
		}
	}
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef NET_21
	iph = nskb->nh.iph;
#else /* NET_21 */
	iph = nskb->ip_hdr;
#endif /* NET_21 */
	zs.next_out = (char *)iph + iphlen;
	zs.avail_out = pyldsz;

	zresult = inflate(&zs, Z_SYNC_FLUSH);

	/* work around a bug in zlib, which sometimes wants to taste an extra
	 * byte when being used in the (undocumented) raw deflate mode.
	 */
	if (zresult == Z_OK && !zs.avail_in && zs.avail_out) {
		__u8 zerostuff = 0;
		
		zs.next_in = &zerostuff;
		zs.avail_in = 1;
		zresult = inflate(&zs, Z_FINISH);
	}

	inflateEnd(&zs);
	if (zresult != Z_STREAM_END) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "inflate() returned error %d (%s), "
			    "skipping decompression.\n",
			    zresult,
			    zs.msg ? zs.msg : zError(zresult));
		*flags |= IPCOMP_DECOMPRESSIONERROR;
		ipsec_kfree_skb(nskb);

		return skb;
	}
	
	/* Update IP header */
	/* resulting decompressed size */
	pyldsz -= zs.avail_out;
	iph->tot_len = htons(iphlen + pyldsz);
	iph->protocol = ((struct ipcomphdr*) ((char*) oiph + iphlen))->ipcomp_nh;
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_decompress: "
		    "spi=%08x, spi&0xffff=%04x, cpi=%04x, payload size: comp=%d, raw=%d, nh=%d.\n",
		    ips ? ntohl(ips->ips_said.spi) : 0,
		    ips ? ntohl(ips->ips_said.spi) & 0x0000ffff : 0,
		    ntohs(((struct ipcomphdr*)(((char*)oiph)+iphlen))->ipcomp_cpi),
		    cpyldsz,
		    pyldsz,
		    iph->protocol);
	
#if 1 /* XXX checksum is done by ipsec_rcv ? */
	iph->check = 0;
	iph->check = ip_fast_csum((char*) iph, iph->ihl);
#endif
	
	/* Update skb length/tail by "unputting" the unused data area */
	skb_put(nskb, -zs.avail_out);
	
	ipsec_kfree_skb(skb);
	
	if (iph->protocol == IPPROTO_COMP)
	{
#ifdef CONFIG_IPSEC_DEBUG
		if(sysctl_ipsec_debug_ipcomp)
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_decompress: "
			    "Eh? inner packet is also compressed, dropping.\n");
#endif /* CONFIG_IPSEC_DEBUG */
		
		ipsec_kfree_skb(nskb);
		return NULL;
	}
	
#ifdef CONFIG_IPSEC_DEBUG
	if(sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int i;
		
		c = (__u8*)iph + iphlen;
		for(i = 0; i < pyldsz; i++, c++) {
			if(!(i % 16)) {
				printk(KERN_INFO "skb_decompress:   result:");
			}
			printk("%02x ", *c);
			if(!((i + 1) % 16)) {
				printk("\n");
			}
		}
		if(i % 16) {
			printk("\n");
		}
	}
#endif /* CONFIG_IPSEC_DEBUG */
	
	return nskb;
}


/* this is derived from skb_copy() in linux 2.2.14 */
/* May be incompatible with other kernel versions!! */
static
struct sk_buff *skb_copy_ipcomp(struct sk_buff *skb, int data_growth, int gfp_mask)
{
        struct sk_buff *n;
	struct iphdr *iph;
        unsigned long offset;
        unsigned int iphlen;
	
	if(!skb) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_copy_ipcomp: "
			    "passed in NULL skb, returning NULL.\n");
		return NULL;
	}

        /*
         *      Allocate the copy buffer
         */
	
#ifdef NET_21
	iph = skb->nh.iph;
#else /* NET_21 */
	iph = skb->ip_hdr;
#endif /* NET_21 */
        if (!iph) return NULL;
        iphlen = iph->ihl << 2;
	
        n=alloc_skb(skb->end - skb->head + data_growth, gfp_mask);
        if(n==NULL)
                return NULL;
	
        /*
         *      Shift between the two data areas in bytes
         */
	
        offset=n->head-skb->head;

        /* Set the data pointer */
        skb_reserve(n,skb->data-skb->head);
        /* Set the tail pointer and length */
        skb_put(n,skb->len+data_growth);
        /* Copy the bytes up to and including the ip header */
        memcpy(n->head,
	       skb->head,
	       ((char *)iph - (char *)skb->head) + iphlen);
        n->list=NULL;
	n->next=NULL;
	n->prev=NULL;
        n->sk=NULL;
        n->dev=skb->dev;
	if (skb->h.raw)
		n->h.raw=skb->h.raw+offset;
	else
		n->h.raw=NULL;
        n->protocol=skb->protocol;
#ifdef NET_21
        n->csum = 0;
        n->priority=skb->priority;
        n->dst=dst_clone(skb->dst);
        n->nh.raw=skb->nh.raw+offset;
#ifndef NETDEV_23
        n->is_clone=0;
#endif /* NETDEV_23 */
        atomic_set(&n->users, 1);
        n->destructor = NULL;
        n->security=skb->security;
        memcpy(n->cb, skb->cb, sizeof(skb->cb));
#ifdef CONFIG_IP_FIREWALL
        n->fwmark = skb->fwmark;
#endif
#else /* NET_21 */
	n->link3=NULL;
	n->when=skb->when;
	n->ip_hdr=(struct iphdr *)(((char *)skb->ip_hdr)+offset);
	n->saddr=skb->saddr;
	n->daddr=skb->daddr;
	n->raddr=skb->raddr;
	n->seq=skb->seq;
	n->end_seq=skb->end_seq;
	n->ack_seq=skb->ack_seq;
	n->acked=skb->acked;
	n->free=1;
	n->arp=skb->arp;
	n->tries=0;
	n->lock=0;
	n->users=0;
	memcpy(n->proto_priv, skb->proto_priv, sizeof(skb->proto_priv));
#endif /* NET_21 */
	if (skb->mac.raw)
		n->mac.raw=skb->mac.raw+offset;
	else
		n->mac.raw=NULL;
#ifndef NETDEV_23
	n->used=skb->used;
#endif /* !NETDEV_23 */
        n->pkt_type=skb->pkt_type;
#ifndef NETDEV_23
	n->pkt_bridged=skb->pkt_bridged;
#endif /* NETDEV_23 */
	n->ip_summed=0;
        n->stamp=skb->stamp;
#ifndef NETDEV_23 /* this seems to have been removed in 2.4 */
#if defined(CONFIG_SHAPER) || defined(CONFIG_SHAPER_MODULE)
        n->shapelatency=skb->shapelatency;       /* Latency on frame */
        n->shapeclock=skb->shapeclock;           /* Time it should go out */
        n->shapelen=skb->shapelen;               /* Frame length in clocks */
        n->shapestamp=skb->shapestamp;           /* Stamp for shaper    */
        n->shapepend=skb->shapepend;             /* Pending */
#endif /* defined(CONFIG_SHAPER) || defined(CONFIG_SHAPER_MODULE) */
#endif /* NETDEV_23 */
#ifdef CONFIG_HIPPI
        n->private.ifield=skb->private.ifield;
#endif /* CONFIG_HIPPI */

        return n;
}
