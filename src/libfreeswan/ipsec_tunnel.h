/*
 * IPSEC tunneling code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003  Richard Guy Briggs.
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
 * RCSID $Id$
 */

#include <linux/types.h>

#ifdef NET_21
# define DEV_QUEUE_XMIT(skb, device, pri) {\
	skb->dev = device; \
	neigh_compat_output(skb); \
	/* skb->dst->output(skb); */ \
 }
# define ICMP_SEND(skb_in, type, code, info, dev) \
	icmp_send(skb_in, type, code, htonl(info))
# define IP_SEND(skb, dev) \
	ip_send(skb);
#else /* NET_21 */
# define DEV_QUEUE_XMIT(skb, device, pri) {\
	dev_queue_xmit(skb, device, pri); \
 }
# define ICMP_SEND(skb_in, type, code, info, dev) \
	icmp_send(skb_in, type, code, info, dev)
# define IP_SEND(skb, dev) \
	if(ntohs(iph->tot_len) > physmtu) { \
		ip_fragment(NULL, skb, dev, 0); \
		ipsec_kfree_skb(skb); \
	} else { \
		dev_queue_xmit(skb, dev, SOPRI_NORMAL); \
	}
#endif /* NET_21 */


/*
 * Heavily based on drivers/net/new_tunnel.c.  Lots
 * of ideas also taken from the 2.1.x version of drivers/net/shaper.c
 */

struct ipsectunnelconf
{
	__u32	cf_cmd;
	union
	{
		char 	cfu_name[12];
	} cf_u;
#define cf_name cf_u.cfu_name
};

#define IPSEC_SET_DEV	(SIOCDEVPRIVATE)
#define IPSEC_DEL_DEV	(SIOCDEVPRIVATE + 1)
#define IPSEC_CLR_DEV	(SIOCDEVPRIVATE + 2)

#ifdef __KERNEL__
#include <linux/version.h>
#ifndef KERNEL_VERSION
#  define KERNEL_VERSION(x,y,z) (((x)<<16)+((y)<<8)+(z))
#endif
struct ipsecpriv
{
	struct sk_buff_head sendq;
	struct device *dev;
	struct wait_queue *wait_queue;
	char locked;
	int  (*hard_start_xmit) (struct sk_buff *skb,
		struct device *dev);
	int  (*hard_header) (struct sk_buff *skb,
		struct device *dev,
		unsigned short type,
		void *daddr,
		void *saddr,
		unsigned len);
#ifdef NET_21
	int  (*rebuild_header)(struct sk_buff *skb);
#else /* NET_21 */
	int  (*rebuild_header)(void *buff, struct device *dev,
			unsigned long raddr, struct sk_buff *skb);
#endif /* NET_21 */
	int  (*set_mac_address)(struct device *dev, void *addr);
#ifndef NET_21
	void (*header_cache_bind)(struct hh_cache **hhp, struct device *dev,
				 unsigned short htype, __u32 daddr);
#endif /* !NET_21 */
	void (*header_cache_update)(struct hh_cache *hh, struct device *dev, unsigned char *  haddr);
	struct net_device_stats *(*get_stats)(struct device *dev);
	struct net_device_stats mystats;
	int mtu;	/* What is the desired MTU? */
};

extern char ipsec_tunnel_c_version[];

extern struct device *ipsecdevices[IPSEC_NUM_IF];

int ipsec_tunnel_init_devices(void);

/* void */ int ipsec_tunnel_cleanup_devices(void);

extern /* void */ int ipsec_init(void);

extern int ipsec_tunnel_start_xmit(struct sk_buff *skb, struct device *dev);

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_tunnel;
extern int sysctl_ipsec_debug_verbose;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */

#ifdef CONFIG_IPSEC_DEBUG
#define DB_TN_INIT	0x0001
#define DB_TN_PROCFS	0x0002
#define DB_TN_XMIT	0x0010
#define DB_TN_OHDR	0x0020
#define DB_TN_CROUT	0x0040
#define DB_TN_OXFS	0x0080
#define DB_TN_REVEC	0x0100
#endif /* CONFIG_IPSEC_DEBUG */
