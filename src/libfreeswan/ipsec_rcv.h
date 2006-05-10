/*
 * 
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
 *
 * RCSID $Id: ipsec_rcv.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */

#define DB_RX_PKTRX	0x0001
#define DB_RX_PKTRX2	0x0002
#define DB_RX_DMP	0x0004
#define DB_RX_IPSA	0x0010
#define DB_RX_XF	0x0020
#define DB_RX_IPAD	0x0040
#define DB_RX_INAU	0x0080
#define DB_RX_OINFO	0x0100
#define DB_RX_OINFO2	0x0200
#define DB_RX_OH	0x0400
#define DB_RX_REPLAY	0x0800

#ifdef __KERNEL__
/* struct options; */

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/config.h>	/* for CONFIG_IP_FORWARD */
#include <linux/version.h>
#include <freeswan.h>

#define IPSEC_BIRTH_TEMPLATE_MAXLEN 256

struct ipsec_birth_reply {
  int            packet_template_len;
  unsigned char  packet_template[IPSEC_BIRTH_TEMPLATE_MAXLEN];
};

extern struct ipsec_birth_reply ipsec_ipv4_birth_packet;
extern struct ipsec_birth_reply ipsec_ipv6_birth_packet;

extern int
#ifdef PROTO_HANDLER_SINGLE_PARM
ipsec_rcv(struct sk_buff *skb);
#else /* PROTO_HANDLER_SINGLE_PARM */
ipsec_rcv(struct sk_buff *skb,
#ifdef NET_21
	  unsigned short xlen);
#else /* NET_21 */
	  struct device *dev,
	  struct options *opt, 
	  __u32 daddr,
	  unsigned short len,
	  __u32 saddr,
	  int redo,
	  struct inet_protocol *protocol);
#endif /* NET_21 */
#endif /* PROTO_HANDLER_SINGLE_PARM */

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_rcv;
#endif /* CONFIG_IPSEC_DEBUG */
extern int sysctl_ipsec_inbound_policy_check;
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_rcv.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.17  2002/09/03 16:32:32  mcr
 * 	definitions of ipsec_birth_reply.
 *
 * Revision 1.16  2002/05/14 02:36:00  rgb
 * Change references to _TDB to _IPSA.
 *
 * Revision 1.15  2002/04/24 07:36:47  mcr
 * Moved from ./klips/net/ipsec/ipsec_rcv.h,v
 *
 * Revision 1.14  2001/09/07 22:15:48  rgb
 * Fix for removal of transport layer protocol handler arg in 2.4.4.
 *
 * Revision 1.13  2001/06/14 19:35:09  rgb
 * Update copyright date.
 *
 * Revision 1.12  2001/03/16 07:36:44  rgb
 * Fixed #endif comment to sate compiler.
 *
 * Revision 1.11  2000/09/21 04:34:21  rgb
 * Moved declaration of sysctl_ipsec_inbound_policy_check outside
 * CONFIG_IPSEC_DEBUG. (MB)
 *
 * Revision 1.10  2000/09/18 02:36:10  rgb
 * Exported sysctl_ipsec_inbound_policy_check for skb_decompress().
 *
 * Revision 1.9  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.8  1999/11/18 04:09:19  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.7  1999/05/25 01:45:37  rgb
 * Fix version macros for 2.0.x as a module.
 *
 * Revision 1.6  1999/05/08 21:24:27  rgb
 * Add includes for 2.2.x include into net/ipv4/protocol.c
 *
 * Revision 1.5  1999/05/05 22:02:32  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.4  1999/04/11 00:28:59  henry
 * GPL boilerplate
 *
 * Revision 1.3  1999/04/06 04:54:27  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.2  1999/01/22 20:06:59  rgb
 * Fixed cut-and-paste error from ipsec_esp.h.
 *
 * Revision 1.1  1999/01/21 20:29:12  rgb
 * Converted from transform switching to algorithm switching.
 *
 * Log: ipsec_esp.h,v 
 * Revision 1.4  1998/08/12 00:07:32  rgb
 * Added data structures for new xforms: null, {,3}dessha1.
 *
 * Revision 1.3  1998/07/14 15:57:01  rgb
 * Add #ifdef __KERNEL__ to protect kernel-only structures.
 *
 * Revision 1.2  1998/06/25 19:33:46  rgb
 * Add prototype for protocol receive function.
 * Rearrange for more logical layout.
 *
 * Revision 1.1  1998/06/18 21:27:45  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.6  1998/06/05 02:28:08  rgb
 * Minor comment fix.
 *
 * Revision 1.5  1998/05/27 22:34:00  rgb
 * Changed structures to accomodate key separation.
 *
 * Revision 1.4  1998/05/18 22:28:43  rgb
 * Disable key printing facilities from /proc/net/ipsec_*.
 *
 * Revision 1.3  1998/04/21 21:29:07  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:20  rgb
 * Updated ESP-3DES-HMAC-MD5-96,
 * 	ESP-DES-HMAC-MD5-96,
 * 	AH-HMAC-MD5-96,
 * 	AH-HMAC-SHA1-96 since Henry started freeswan cvs repository
 * from old standards (RFC182[5-9] to new (as of March 1998) drafts.
 *
 * Fixed eroute references in /proc/net/ipsec*.
 *
 * Started to patch module unloading memory leaks in ipsec_netlink and
 * radij tree unloading.
 *
 * Revision 1.1  1998/04/09 03:06:00  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:24:48  ji
 * Added ESP-3DES-MD5-96 transform.
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Added definitions for new ESP transforms.
 *
 * Revision 0.3  1996/11/20 14:35:48  ji
 * Minor Cleanup.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */


