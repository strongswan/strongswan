/*
 * IPSEC MAST code.
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002  Richard Guy Briggs.
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

char ipsec_mast_c_version[] = "RCSID $Id: ipsec_mast.c,v 1.2 2004/06/13 19:57:49 as Exp $";

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/config.h>	/* for CONFIG_IP_FORWARD */
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

#include <linux/netdevice.h>   /* struct device, struct net_device_stats, dev_queue_xmit() and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/skbuff.h>
#include <freeswan.h>
#include <asm/uaccess.h>
#include <linux/in6.h>
#include <net/dst.h>
#undef dev_kfree_skb
#define dev_kfree_skb(a,b) kfree_skb(a)
#define PHYSDEV_TYPE
#include <asm/checksum.h>
#include <net/icmp.h>		/* icmp_send() */
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>

#include <linux/if_arp.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_life.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_eroute.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_sa.h"
#include "freeswan/ipsec_tunnel.h"
#include "freeswan/ipsec_mast.h"
#include "freeswan/ipsec_ipe4.h"
#include "freeswan/ipsec_ah.h"
#include "freeswan/ipsec_esp.h"

#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/ipsec_proto.h"

int ipsec_maxdevice_count = -1;

DEBUG_NO_STATIC int
ipsec_mast_open(struct device *dev)
{
	struct ipsecpriv *prv = dev->priv;
	
	/*
	 * Can't open until attached.
	 */

	KLIPS_PRINT(debug_mast & DB_MAST_INIT,
		    "klips_debug:ipsec_mast_open: "
		    "dev = %s, prv->dev = %s\n",
		    dev->name, prv->dev?prv->dev->name:"NONE");

	if (prv->dev == NULL)
		return -ENODEV;
	
	MOD_INC_USE_COUNT;
	return 0;
}

DEBUG_NO_STATIC int
ipsec_mast_close(struct device *dev)
{
	MOD_DEC_USE_COUNT;
	return 0;
}

static inline int ipsec_mast_xmit2(struct sk_buff *skb)
{
	return ip_send(skb);
}

enum ipsec_xmit_value
ipsec_mast_send(struct ipsec_xmit_state*ixs)
{
	/* new route/dst cache code from James Morris */
	ixs->skb->dev = ixs->physdev;
	/*skb_orphan(ixs->skb);*/
	if((ixs->error = ip_route_output(&ixs->route,
				    ixs->skb->nh.iph->daddr,
				    ixs->pass ? 0 : ixs->skb->nh.iph->saddr,
				    RT_TOS(ixs->skb->nh.iph->tos),
				    ixs->physdev->iflink /* rgb: should this be 0? */))) {
		ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
			    "klips_debug:ipsec_xmit_send: "
			    "ip_route_output failed with error code %d, rt->u.dst.dev=%s, dropped\n",
			    ixs->error,
			    ixs->route->u.dst.dev->name);
		return IPSEC_XMIT_ROUTEERR;
	}
	if(ixs->dev == ixs->route->u.dst.dev) {
		ip_rt_put(ixs->route);
		/* This is recursion, drop it. */
		ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
			    "klips_debug:ipsec_xmit_send: "
			    "suspect recursion, dev=rt->u.dst.dev=%s, dropped\n",
			    ixs->dev->name);
		return IPSEC_XMIT_RECURSDETECT;
	}
	dst_release(ixs->skb->dst);
	ixs->skb->dst = &ixs->route->u.dst;
	ixs->stats->tx_bytes += ixs->skb->len;
	if(ixs->skb->len < ixs->skb->nh.raw - ixs->skb->data) {
		ixs->stats->tx_errors++;
		printk(KERN_WARNING
		       "klips_error:ipsec_xmit_send: "
		       "tried to __skb_pull nh-data=%ld, %d available.  This should never happen, please report.\n",
		       (unsigned long)(ixs->skb->nh.raw - ixs->skb->data),
		       ixs->skb->len);
		return IPSEC_XMIT_PUSHPULLERR;
	}
	__skb_pull(ixs->skb, ixs->skb->nh.raw - ixs->skb->data);
#ifdef SKB_RESET_NFCT
	nf_conntrack_put(ixs->skb->nfct);
	ixs->skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	ixs->skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* SKB_RESET_NFCT */
	KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
		    "klips_debug:ipsec_xmit_send: "
		    "...done, calling ip_send() on device:%s\n",
		    ixs->skb->dev ? ixs->skb->dev->name : "NULL");
	KLIPS_IP_PRINT(debug_mast & DB_MAST_XMIT, ixs->skb->nh.iph);
	{
		int err;

		err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, ixs->skb, NULL, ixs->route->u.dst.dev,
			      ipsec_mast_xmit2);
		if(err != NET_XMIT_SUCCESS && err != NET_XMIT_CN) {
			if(net_ratelimit())
				printk(KERN_ERR
				       "klips_error:ipsec_xmit_send: "
				       "ip_send() failed, err=%d\n", 
				       -err);
			ixs->stats->tx_errors++;
			ixs->stats->tx_aborted_errors++;
			ixs->skb = NULL;
			return IPSEC_XMIT_IPSENDFAILURE;
		}
	}
	ixs->stats->tx_packets++;

	ixs->skb = NULL;
	
	return IPSEC_XMIT_OK;
}

void
ipsec_mast_cleanup(struct ipsec_xmit_state*ixs)
{
#if defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE)
	netif_wake_queue(ixs->dev);
#else /* defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE) */
	ixs->dev->tbusy = 0;
#endif /* defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE) */
	if(ixs->saved_header) {
		kfree(ixs->saved_header);
	}
	if(ixs->skb) {
		dev_kfree_skb(ixs->skb, FREE_WRITE);
	}
	if(ixs->oskb) {
		dev_kfree_skb(ixs->oskb, FREE_WRITE);
	}
	if (ixs->ips.ips_ident_s.data) {
		kfree(ixs->ips.ips_ident_s.data);
	}
	if (ixs->ips.ips_ident_d.data) {
		kfree(ixs->ips.ips_ident_d.data);
	}
}

#if 0
/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */
int
ipsec_mast_start_xmit(struct sk_buff *skb, struct device *dev, IPsecSAref_t SAref)
{
	struct ipsec_xmit_state ixs_mem;
	struct ipsec_xmit_state *ixs = &ixs_mem;
	enum ipsec_xmit_value stat = IPSEC_XMIT_OK;

	/* dev could be a mast device, but should be optional, I think... */
	/* SAref is also optional, but one of the two must be present. */
	/* I wonder if it could accept no device or saref and guess? */

/*	ipsec_xmit_sanity_check_dev(ixs); */

	ipsec_xmit_sanity_check_skb(ixs);

	ipsec_xmit_adjust_hard_header(ixs);

	stat = ipsec_xmit_encap_bundle(ixs);
	if(stat != IPSEC_XMIT_OK) {
		/* SA processing failed */
	}

	ipsec_xmit_hard_header_restore();
}
#endif

DEBUG_NO_STATIC struct net_device_stats *
ipsec_mast_get_stats(struct device *dev)
{
	return &(((struct ipsecpriv *)(dev->priv))->mystats);
}

/*
 * Revectored calls.
 * For each of these calls, a field exists in our private structure.
 */

DEBUG_NO_STATIC int
ipsec_mast_hard_header(struct sk_buff *skb, struct device *dev,
	unsigned short type, void *daddr, void *saddr, unsigned len)
{
	struct ipsecpriv *prv = dev->priv;
	struct device *tmp;
	int ret;
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(skb == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no skb...\n");
		return -ENODATA;
	}

	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no device...\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_hard_header: "
		    "skb->dev=%s dev=%s.\n",
		    skb->dev ? skb->dev->name : "NULL",
		    dev->name);
	
	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no private space associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no physical device associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	/* check if we have to send a IPv6 packet. It might be a Router
	   Solicitation, where the building of the packet happens in
	   reverse order:
	   1. ll hdr,
	   2. IPv6 hdr,
	   3. ICMPv6 hdr
	   -> skb->nh.raw is still uninitialized when this function is
	   called!!  If this is no IPv6 packet, we can print debugging
	   messages, otherwise we skip all debugging messages and just
	   build the ll header */
	if(type != ETH_P_IPV6) {
		/* execute this only, if we don't have to build the
		   header for a IPv6 packet */
		if(!prv->hard_header) {
			KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
				    "klips_debug:ipsec_mast_hard_header: "
				    "physical device has been detached, packet dropped 0p%p->0p%p len=%d type=%d dev=%s->NULL ",
				    saddr,
				    daddr,
				    len,
				    type,
				    dev->name);
			KLIPS_PRINTMORE(debug_mast & DB_MAST_REVEC,
					"ip=%08x->%08x\n",
					(__u32)ntohl(skb->nh.iph->saddr),
					(__u32)ntohl(skb->nh.iph->daddr) );
			stats->tx_dropped++;
			return -ENODEV;
		}
		
#define da ((struct device *)(prv->dev))->dev_addr
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "Revectored 0p%p->0p%p len=%d type=%d dev=%s->%s dev_addr=%02x:%02x:%02x:%02x:%02x:%02x ",
			    saddr,
			    daddr,
			    len,
			    type,
			    dev->name,
			    prv->dev->name,
			    da[0], da[1], da[2], da[3], da[4], da[5]);
		KLIPS_PRINTMORE(debug_mast & DB_MAST_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(skb->nh.iph->saddr),
			    (__u32)ntohl(skb->nh.iph->daddr) );
	} else {
		KLIPS_PRINT(debug_mast,
			    "klips_debug:ipsec_mast_hard_header: "
			    "is IPv6 packet, skip debugging messages, only revector and build linklocal header.\n");
	}                                                                       
	tmp = skb->dev;
	skb->dev = prv->dev;
	ret = prv->hard_header(skb, prv->dev, type, (void *)daddr, (void *)saddr, len);
	skb->dev = tmp;
	return ret;
}

DEBUG_NO_STATIC int
ipsec_mast_rebuild_header(struct sk_buff *skb)
{
	struct ipsecpriv *prv = skb->dev->priv;
	struct device *tmp;
	int ret;
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(skb->dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_rebuild_header: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_rebuild_header: "
			    "no private space associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_rebuild_header: "
			    "no physical device associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if(!prv->rebuild_header) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_rebuild_header: "
			    "physical device has been detached, packet dropped skb->dev=%s->NULL ",
			    skb->dev->name);
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(skb->nh.iph->saddr),
			    (__u32)ntohl(skb->nh.iph->daddr) );
		stats->tx_dropped++;
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast: "
		    "Revectored rebuild_header dev=%s->%s ",
		    skb->dev->name, prv->dev->name);
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "ip=%08x->%08x\n",
		    (__u32)ntohl(skb->nh.iph->saddr),
		    (__u32)ntohl(skb->nh.iph->daddr) );
	tmp = skb->dev;
	skb->dev = prv->dev;
	
	ret = prv->rebuild_header(skb);
	skb->dev = tmp;
	return ret;
}

DEBUG_NO_STATIC int
ipsec_mast_set_mac_address(struct device *dev, void *addr)
{
	struct ipsecpriv *prv = dev->priv;
	
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_set_mac_address: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_set_mac_address: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_set_mac_address: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if(!prv->set_mac_address) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_set_mac_address: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_set_mac_address: "
		    "Revectored dev=%s->%s addr=0p%p\n",
		    dev->name, prv->dev->name, addr);
	return prv->set_mac_address(prv->dev, addr);

}

DEBUG_NO_STATIC void
ipsec_mast_cache_update(struct hh_cache *hh, struct device *dev, unsigned char *  haddr)
{
	struct ipsecpriv *prv = dev->priv;
	
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no device...");
		return;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return;
	}

	if(!prv->header_cache_update) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		return;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast: "
		    "Revectored cache_update\n");
	prv->header_cache_update(hh, prv->dev, haddr);
	return;
}

DEBUG_NO_STATIC int
ipsec_mast_neigh_setup(struct neighbour *n)
{
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_neigh_setup:\n");

        if (n->nud_state == NUD_NONE) {
                n->ops = &arp_broken_ops;
                n->output = n->ops->output;
        }
        return 0;
}

DEBUG_NO_STATIC int
ipsec_mast_neigh_setup_dev(struct device *dev, struct neigh_parms *p)
{
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_neigh_setup_dev: "
		    "setting up %s\n",
		    dev ? dev->name : "NULL");

        if (p->tbl->family == AF_INET) {
                p->neigh_setup = ipsec_mast_neigh_setup;
                p->ucast_probes = 0;
                p->mcast_probes = 0;
        }
        return 0;
}

/*
 * We call the attach routine to attach another device.
 */

DEBUG_NO_STATIC int
ipsec_mast_attach(struct device *dev, struct device *physdev)
{
        int i;
	struct ipsecpriv *prv = dev->priv;

	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_attach: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_attach: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODATA;
	}

	prv->dev = physdev;
	prv->hard_start_xmit = physdev->hard_start_xmit;
	prv->get_stats = physdev->get_stats;

	if (physdev->hard_header) {
		prv->hard_header = physdev->hard_header;
		dev->hard_header = ipsec_mast_hard_header;
	} else
		dev->hard_header = NULL;
	
	if (physdev->rebuild_header) {
		prv->rebuild_header = physdev->rebuild_header;
		dev->rebuild_header = ipsec_mast_rebuild_header;
	} else
		dev->rebuild_header = NULL;
	
	if (physdev->set_mac_address) {
		prv->set_mac_address = physdev->set_mac_address;
		dev->set_mac_address = ipsec_mast_set_mac_address;
	} else
		dev->set_mac_address = NULL;
	
	if (physdev->header_cache_update) {
		prv->header_cache_update = physdev->header_cache_update;
		dev->header_cache_update = ipsec_mast_cache_update;
	} else
		dev->header_cache_update = NULL;

	dev->hard_header_len = physdev->hard_header_len;

/*	prv->neigh_setup        = physdev->neigh_setup; */
	dev->neigh_setup        = ipsec_mast_neigh_setup_dev;
	dev->mtu = 16260; /* 0xfff0; */ /* dev->mtu; */
	prv->mtu = physdev->mtu;

#ifdef PHYSDEV_TYPE
	dev->type = physdev->type; /* ARPHRD_MAST; */
#endif /*  PHYSDEV_TYPE */

	dev->addr_len = physdev->addr_len;
	for (i=0; i<dev->addr_len; i++) {
		dev->dev_addr[i] = physdev->dev_addr[i];
	}
#ifdef CONFIG_IPSEC_DEBUG
	if(debug_mast & DB_MAST_INIT) {
		printk(KERN_INFO "klips_debug:ipsec_mast_attach: "
		       "physical device %s being attached has HW address: %2x",
		       physdev->name, physdev->dev_addr[0]);
		for (i=1; i < physdev->addr_len; i++) {
			printk(":%02x", physdev->dev_addr[i]);
		}
		printk("\n");
	}
#endif /* CONFIG_IPSEC_DEBUG */

	return 0;
}

/*
 * We call the detach routine to detach the ipsec mast from another device.
 */

DEBUG_NO_STATIC int
ipsec_mast_detach(struct device *dev)
{
        int i;
	struct ipsecpriv *prv = dev->priv;

	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_detach: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_detach: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODATA;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_INIT,
		    "klips_debug:ipsec_mast_detach: "
		    "physical device %s being detached from virtual device %s\n",
		    prv->dev ? prv->dev->name : "NULL",
		    dev->name);

	prv->dev = NULL;
	prv->hard_start_xmit = NULL;
	prv->get_stats = NULL;

	prv->hard_header = NULL;
#ifdef DETACH_AND_DOWN
	dev->hard_header = NULL;
#endif /* DETACH_AND_DOWN */
	
	prv->rebuild_header = NULL;
#ifdef DETACH_AND_DOWN
	dev->rebuild_header = NULL;
#endif /* DETACH_AND_DOWN */
	
	prv->set_mac_address = NULL;
#ifdef DETACH_AND_DOWN
	dev->set_mac_address = NULL;
#endif /* DETACH_AND_DOWN */
	
	prv->header_cache_update = NULL;
#ifdef DETACH_AND_DOWN
	dev->header_cache_update = NULL;
#endif /* DETACH_AND_DOWN */

#ifdef DETACH_AND_DOWN
	dev->neigh_setup        = NULL;
#endif /* DETACH_AND_DOWN */

	dev->hard_header_len = 0;
#ifdef DETACH_AND_DOWN
	dev->mtu = 0;
#endif /* DETACH_AND_DOWN */
	prv->mtu = 0;
	for (i=0; i<MAX_ADDR_LEN; i++) {
		dev->dev_addr[i] = 0;
	}
	dev->addr_len = 0;
#ifdef PHYSDEV_TYPE
	dev->type = ARPHRD_VOID; /* ARPHRD_MAST; */
#endif /*  PHYSDEV_TYPE */
	
	return 0;
}

/*
 * We call the clear routine to detach all ipsec masts from other devices.
 */
DEBUG_NO_STATIC int
ipsec_mast_clear(void)
{
	int i;
	struct device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	char name[9];
	int ret;

	KLIPS_PRINT(debug_mast & DB_MAST_INIT,
		    "klips_debug:ipsec_mast_clear: .\n");

	for(i = 0; i < IPSEC_NUM_IF; i++) {
		sprintf(name, IPSEC_DEV_FORMAT, i);
		if((ipsecdev = ipsec_dev_get(name)) != NULL) {
			if((prv = (struct ipsecpriv *)(ipsecdev->priv))) {
				prvdev = (struct device *)(prv->dev);
				if(prvdev) {
					KLIPS_PRINT(debug_mast & DB_MAST_INIT,
						    "klips_debug:ipsec_mast_clear: "
						    "physical device for device %s is %s\n",
						    name, prvdev->name);
					if((ret = ipsec_mast_detach(ipsecdev))) {
						KLIPS_PRINT(debug_mast & DB_MAST_INIT,
							    "klips_debug:ipsec_mast_clear: "
							    "error %d detatching device %s from device %s.\n",
							    ret, name, prvdev->name);
						return ret;
					}
				}
			}
		}
	}
	return 0;
}

DEBUG_NO_STATIC int
ipsec_mast_ioctl(struct device *dev, struct ifreq *ifr, int cmd)
{
	struct ipsecmastconf *cf = (struct ipsecmastconf *)&ifr->ifr_data;
	struct ipsecpriv *prv = dev->priv;
	struct device *them; /* physical device */
#ifdef CONFIG_IP_ALIAS
	char *colon;
	char realphysname[IFNAMSIZ];
#endif /* CONFIG_IP_ALIAS */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "device not supplied.\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_INIT,
		    "klips_debug:ipsec_mast_ioctl: "
		    "tncfg service call #%d for dev=%s\n",
		    cmd,
		    dev->name ? dev->name : "NULL");
	switch (cmd) {
	/* attach a virtual ipsec? device to a physical device */
	case IPSEC_SET_DEV:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "calling ipsec_mast_attatch...\n");
#ifdef CONFIG_IP_ALIAS
		/* If this is an IP alias interface, get its real physical name */
		strncpy(realphysname, cf->cf_name, IFNAMSIZ);
		realphysname[IFNAMSIZ-1] = 0;
		colon = strchr(realphysname, ':');
		if (colon) *colon = 0;
		them = ipsec_dev_get(realphysname);
#else /* CONFIG_IP_ALIAS */
		them = ipsec_dev_get(cf->cf_name);
#endif /* CONFIG_IP_ALIAS */

		if (them == NULL) {
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_ioctl: "
				    "physical device %s requested is null\n",
				    cf->cf_name);
			return -ENXIO;
		}
		
#if 0
		if (them->flags & IFF_UP) {
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_ioctl: "
				    "physical device %s requested is not up.\n",
				    cf->cf_name);
			return -ENXIO;
		}
#endif
		
		if (prv && prv->dev) {
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_ioctl: "
				    "virtual device is already connected to %s.\n",
				    prv->dev->name ? prv->dev->name : "NULL");
			return -EBUSY;
		}
		return ipsec_mast_attach(dev, them);

	case IPSEC_DEL_DEV:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "calling ipsec_mast_detatch.\n");
		if (! prv->dev) {
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_ioctl: "
				    "physical device not connected.\n");
			return -ENODEV;
		}
		return ipsec_mast_detach(dev);
	       
	case IPSEC_CLR_DEV:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "calling ipsec_mast_clear.\n");
		return ipsec_mast_clear();

	default:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "unknown command %d.\n",
			    cmd);
		return -EOPNOTSUPP;
	}
}

int
ipsec_mast_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct device *dev = ptr;
	struct device *ipsec_dev;
	struct ipsecpriv *priv;
	char name[9];
	int i;

	if (dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "dev=NULL for event type %ld.\n",
			    event);
		return(NOTIFY_DONE);
	}

	/* check for loopback devices */
	if (dev && (dev->flags & IFF_LOOPBACK)) {
		return(NOTIFY_DONE);
	}

	switch (event) {
	case NETDEV_DOWN:
		/* look very carefully at the scope of these compiler
		   directives before changing anything... -- RGB */

	case NETDEV_UNREGISTER:
		switch (event) {
		case NETDEV_DOWN:
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_device_event: "
				    "NETDEV_DOWN dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			if(strncmp(dev->name, "ipsec", strlen("ipsec")) == 0) {
				printk(KERN_CRIT "IPSEC EVENT: KLIPS device %s shut down.\n",
				       dev->name);
			}
			break;
		case NETDEV_UNREGISTER:
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_device_event: "
				    "NETDEV_UNREGISTER dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			break;
		}
		
		/* find the attached physical device and detach it. */
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, IPSEC_DEV_FORMAT, i);
			ipsec_dev = ipsec_dev_get(name);
			if(ipsec_dev) {
				priv = (struct ipsecpriv *)(ipsec_dev->priv);
				if(priv) {
					;
					if(((struct device *)(priv->dev)) == dev) {
						/* dev_close(ipsec_dev); */
						/* return */ ipsec_mast_detach(ipsec_dev);
						KLIPS_PRINT(debug_mast & DB_MAST_INIT,
							    "klips_debug:ipsec_mast_device_event: "
							    "device '%s' has been detached.\n",
							    ipsec_dev->name);
						break;
					}
				} else {
					KLIPS_PRINT(debug_mast & DB_MAST_INIT,
						    "klips_debug:ipsec_mast_device_event: "
						    "device '%s' has no private data space!\n",
						    ipsec_dev->name);
				}
			}
		}
		break;
	case NETDEV_UP:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_UP dev=%s\n",
			    dev->name);
		break;
	case NETDEV_REBOOT:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_REBOOT dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGE:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGE dev=%s flags=%x\n",
			    dev->name,
			    dev->flags);
		break;
	case NETDEV_REGISTER:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_REGISTER dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGEMTU:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGEMTU dev=%s to mtu=%d\n",
			    dev->name,
			    dev->mtu);
		break;
	case NETDEV_CHANGEADDR:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGEADDR dev=%s\n",
			    dev->name);
		break;
	case NETDEV_GOING_DOWN:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_GOING_DOWN dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGENAME:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGENAME dev=%s\n",
			    dev->name);
		break;
	default:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "event type %ld unrecognised for dev=%s\n",
			    event,
			    dev->name);
		break;
	}
	return NOTIFY_DONE;
}

/*
 *	Called when an ipsec mast device is initialized.
 *	The ipsec mast device structure is passed to us.
 */
 
int
ipsec_mast_init(struct device *dev)
{
	int i;

	KLIPS_PRINT(debug_mast,
		    "klips_debug:ipsec_mast_init: "
		    "allocating %lu bytes initialising device: %s\n",
		    (unsigned long) sizeof(struct ipsecpriv),
		    dev->name ? dev->name : "NULL");

	/* Add our mast functions to the device */
	dev->open		= ipsec_mast_open;
	dev->stop		= ipsec_mast_close;
	dev->hard_start_xmit	= ipsec_mast_start_xmit;
	dev->get_stats		= ipsec_mast_get_stats;

	dev->priv = kmalloc(sizeof(struct ipsecpriv), GFP_KERNEL);
	if (dev->priv == NULL)
		return -ENOMEM;
	memset((caddr_t)(dev->priv), 0, sizeof(struct ipsecpriv));

	for(i = 0; i < sizeof(zeroes); i++) {
		((__u8*)(zeroes))[i] = 0;
	}
	
	dev->set_multicast_list = NULL;
	dev->do_ioctl		= ipsec_mast_ioctl;
	dev->hard_header	= NULL;
	dev->rebuild_header 	= NULL;
	dev->set_mac_address 	= NULL;
	dev->header_cache_update= NULL;
	dev->neigh_setup        = ipsec_mast_neigh_setup_dev;
	dev->hard_header_len 	= 0;
	dev->mtu		= 0;
	dev->addr_len		= 0;
	dev->type		= ARPHRD_VOID; /* ARPHRD_MAST; */ /* ARPHRD_ETHER; */
	dev->tx_queue_len	= 10;		/* Small queue */
	memset((caddr_t)(dev->broadcast),0xFF, ETH_ALEN);	/* what if this is not attached to ethernet? */

	/* New-style flags. */
	dev->flags		= IFF_NOARP /* 0 */ /* Petr Novak */;
	dev_init_buffers(dev);

	/* We're done.  Have I forgotten anything? */
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*  Module specific interface (but it links with the rest of IPSEC)  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

int
ipsec_mast_probe(struct device *dev)
{
	ipsec_mast_init(dev); 
	return 0;
}

int 
ipsec_mast_init_devices(void)
{
	return 0;
}

/* void */
int
ipsec_mast_cleanup_devices(void)
{
	int error = 0;
	int i;
	char name[10];
	struct device *dev_mast;
	
	for(i = 0; i < ipsec_mastdevice_count; i++) {
		sprintf(name, MAST_DEV_FORMAT, i);
		if((dev_mast = ipsec_dev_get(name)) == NULL) {
			break;
		}
		unregister_netdev(dev_mast);
		kfree(dev_mast->priv);
		dev_mast->priv=NULL;
	}
	return error;
}
