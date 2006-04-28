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
 * RCSID $Id: ipsec_tunnel.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */


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

/*
 * $Log: ipsec_tunnel.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.28  2003/06/24 20:22:32  mcr
 * 	added new global: ipsecdevices[] so that we can keep track of
 * 	the ipsecX devices. They will be referenced with dev_hold(),
 * 	so 2.2 may need this as well.
 *
 * Revision 1.27  2003/04/03 17:38:09  rgb
 * Centralised ipsec_kfree_skb and ipsec_dev_{get,put}.
 *
 * Revision 1.26  2003/02/12 19:32:20  rgb
 * Updated copyright year.
 *
 * Revision 1.25  2002/05/27 18:56:07  rgb
 * Convert to dynamic ipsec device allocation.
 *
 * Revision 1.24  2002/04/24 07:36:48  mcr
 * Moved from ./klips/net/ipsec/ipsec_tunnel.h,v
 *
 * Revision 1.23  2001/11/06 19:50:44  rgb
 * Moved IP_SEND, ICMP_SEND, DEV_QUEUE_XMIT macros to ipsec_tunnel.h for
 * use also by pfkey_v2_parser.c
 *
 * Revision 1.22  2001/09/15 16:24:05  rgb
 * Re-inject first and last HOLD packet when an eroute REPLACE is done.
 *
 * Revision 1.21  2001/06/14 19:35:10  rgb
 * Update copyright date.
 *
 * Revision 1.20  2000/09/15 11:37:02  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.19  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.18  2000/07/28 13:50:54  rgb
 * Changed enet_statistics to net_device_stats and added back compatibility
 * for pre-2.1.19.
 *
 * Revision 1.17  1999/11/19 01:12:15  rgb
 * Purge unneeded proc_info prototypes, now that static linking uses
 * dynamic proc_info registration.
 *
 * Revision 1.16  1999/11/18 18:51:00  rgb
 * Changed all device registrations for static linking to
 * dynamic to reduce the number and size of patches.
 *
 * Revision 1.15  1999/11/18 04:14:21  rgb
 * Replaced all kernel version macros to shorter, readable form.
 * Added CONFIG_PROC_FS compiler directives in case it is shut off.
 * Added Marc Boucher's 2.3.25 proc patches.
 *
 * Revision 1.14  1999/05/25 02:50:10  rgb
 * Fix kernel version macros for 2.0.x static linking.
 *
 * Revision 1.13  1999/05/25 02:41:06  rgb
 * Add ipsec_klipsdebug support for static linking.
 *
 * Revision 1.12  1999/05/05 22:02:32  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.11  1999/04/29 15:19:50  rgb
 * Add return values to init and cleanup functions.
 *
 * Revision 1.10  1999/04/16 16:02:39  rgb
 * Bump up macro to 4 ipsec I/Fs.
 *
 * Revision 1.9  1999/04/15 15:37:25  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.5.2.1  1999/04/02 04:26:14  rgb
 * Backcheck from HEAD, pre1.0.
 *
 * Revision 1.8  1999/04/11 00:29:01  henry
 * GPL boilerplate
 *
 * Revision 1.7  1999/04/06 04:54:28  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.6  1999/03/31 05:44:48  rgb
 * Keep PMTU reduction private.
 *
 * Revision 1.5  1999/02/10 22:31:20  rgb
 * Change rebuild_header member to reflect generality of link layer.
 *
 * Revision 1.4  1998/12/01 13:22:04  rgb
 * Added support for debug printing of version info.
 *
 * Revision 1.3  1998/07/29 20:42:46  rgb
 * Add a macro for clearing all tunnel devices.
 * Rearrange structures and declarations for sharing with userspace.
 *
 * Revision 1.2  1998/06/25 20:01:45  rgb
 * Make prototypes available for ipsec_init and ipsec proc_dir_entries
 * for static linking.
 *
 * Revision 1.1  1998/06/18 21:27:50  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.3  1998/05/18 21:51:50  rgb
 * Added macros for num of I/F's and a procfs debug switch.
 *
 * Revision 1.2  1998/04/21 21:29:09  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:06:13  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:05  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:24:48  ji
 * Added transport mode.
 * Changed the way routing is done.
 * Lots of bug fixes.
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * No changes.
 *
 * Revision 0.3  1996/11/20 14:39:04  ji
 * Minor cleanups.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
