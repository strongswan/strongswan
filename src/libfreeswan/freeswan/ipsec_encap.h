/*
 * declarations relevant to encapsulation-like operations
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
 * RCSID $Id: ipsec_encap.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */

#ifndef _IPSEC_ENCAP_H_

#define SENT_IP4	16	/* data is two struct in_addr + proto + ports*/
			/* (2 * sizeof(struct in_addr)) */
			/* sizeof(struct sockaddr_encap)
			   - offsetof(struct sockaddr_encap, Sen.Sip4.Src) */

struct sockaddr_encap
{
	__u8	sen_len;		/* length */
	__u8	sen_family;		/* AF_ENCAP */
	__u16	sen_type;		/* see SENT_* */
	union
	{
		struct			/* SENT_IP4 */
		{
			struct in_addr Src;
			struct in_addr Dst;
			__u8 Proto;
			__u16 Sport;
			__u16 Dport;
		} Sip4;
	} Sen;
};

#define sen_ip_src	Sen.Sip4.Src
#define sen_ip_dst	Sen.Sip4.Dst
#define sen_proto       Sen.Sip4.Proto
#define sen_sport       Sen.Sip4.Sport
#define sen_dport       Sen.Sip4.Dport

#ifndef AF_ENCAP
#define AF_ENCAP 26
#endif /* AF_ENCAP */

#define _IPSEC_ENCAP_H_
#endif /* _IPSEC_ENCAP_H_ */

/*
 * $Log: ipsec_encap.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.17  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_encap.h,v
 *
 * Revision 1.16  2001/11/26 09:23:47  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.15.2.1  2001/09/25 02:18:54  mcr
 * 	struct eroute moved to ipsec_eroute.h
 *
 * Revision 1.15  2001/09/14 16:58:36  rgb
 * Added support for storing the first and last packets through a HOLD.
 *
 * Revision 1.14  2001/09/08 21:13:31  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.13  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.12  2001/05/27 06:12:10  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.11  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.10  2000/03/22 16:15:36  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.9  2000/01/21 06:13:26  rgb
 * Added a macro for AF_ENCAP
 *
 * Revision 1.8  1999/12/31 14:56:55  rgb
 * MB fix for 2.3 dev-use-count.
 *
 * Revision 1.7  1999/11/18 04:09:18  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.6  1999/09/24 00:34:13  rgb
 * Add Marc Boucher's support for 2.3.xx+.
 *
 * Revision 1.5  1999/04/11 00:28:57  henry
 * GPL boilerplate
 *
 * Revision 1.4  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.3  1998/10/19 14:44:28  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.2  1998/07/14 18:19:33  rgb
 * Added #ifdef __KERNEL__ directives to restrict scope of header.
 *
 * Revision 1.1  1998/06/18 21:27:44  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.2  1998/04/21 21:29:10  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:05:58  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Minor cosmetic changes.
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
