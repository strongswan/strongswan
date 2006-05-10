/*
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
 * RCSID $Id: ipsec_esp.h,v 1.2 2004/03/22 21:53:18 as Exp $
 */

#include "freeswan/ipsec_md5h.h"
#include "freeswan/ipsec_sha1.h"

#include "crypto/des.h"

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif /* IPPROTO_ESP */

#define ESP_HEADER_LEN		8	/* 64 bits header (spi+rpl)*/

#define EMT_ESPDESCBC_ULEN	20	/* coming from user mode */
#define EMT_ESPDES_KMAX		64	/* 512 bit secret key enough? */
#define EMT_ESPDES_KEY_SZ	8	/* 56 bit secret key with parity = 64 bits */
#define EMT_ESP3DES_KEY_SZ	24	/* 168 bit secret key with parity = 192 bits */
#define EMT_ESPDES_IV_SZ	8	/* IV size */
#define ESP_DESCBC_BLKLEN       8       /* DES-CBC block size */

#define ESP_IV_MAXSZ		16	/* This is _critical_ */
#define ESP_IV_MAXSZ_INT	(ESP_IV_MAXSZ/sizeof(int))

#define DB_ES_PKTRX	0x0001
#define DB_ES_PKTRX2	0x0002
#define DB_ES_IPSA	0x0010
#define DB_ES_XF	0x0020
#define DB_ES_IPAD	0x0040
#define DB_ES_INAU	0x0080
#define DB_ES_OINFO	0x0100
#define DB_ES_OINFO2	0x0200
#define DB_ES_OH	0x0400
#define DB_ES_REPLAY	0x0800

#ifdef __KERNEL__
struct des_eks {
	des_key_schedule ks;
};

extern struct inet_protocol esp_protocol;

struct options;

extern int
esp_rcv(struct sk_buff *skb,
	struct device *dev,
	struct options *opt, 
	__u32 daddr,
	unsigned short len,
	__u32 saddr,
	int redo,
	struct inet_protocol *protocol);

/* Only for 64 bits IVs, eg. ESP_3DES :P */
struct esphdr
{
	__u32	esp_spi;		/* Security Parameters Index */
        __u32   esp_rpl;                /* Replay counter */
	__u8	esp_iv[8];		/* iv */
};

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_esp;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_esp.h,v $
 * Revision 1.2  2004/03/22 21:53:18  as
 * merged alg-0.8.1 branch with HEAD
 *
 * Revision 1.1.4.1  2004/03/16 09:48:18  as
 * alg-0.8.1rc12 patch merged
 *
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.21  2003/02/06 02:21:34  rgb
 *
 * Moved "struct auth_alg" from ipsec_rcv.c to ipsec_ah.h .
 * Changed "struct ah" to "struct ahhdr" and "struct esp" to "struct esphdr".
 * Removed "#ifdef INBOUND_POLICY_CHECK_eroute" dead code.
 *
 * Revision 1.20  2002/05/14 02:37:02  rgb
 * Change reference from _TDB to _IPSA.
 *
 * Revision 1.19  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.18  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_esp.h,v
 *
 * Revision 1.17  2002/02/20 01:27:07  rgb
 * Ditched a pile of structs only used by the old Netlink interface.
 *
 * Revision 1.16  2001/12/11 02:35:57  rgb
 * Change "struct net_device" to "struct device" for 2.2 compatibility.
 *
 * Revision 1.15  2001/11/26 09:23:48  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.14.2.3  2001/10/23 04:16:42  mcr
 * 	get definition of des_key_schedule from des.h
 *
 * Revision 1.14.2.2  2001/10/22 20:33:13  mcr
 * 	use "des_key_schedule" structure instead of cooking our own.
 *
 * Revision 1.14.2.1  2001/09/25 02:18:25  mcr
 * 	replace "struct device" with "struct netdevice"
 *
 * Revision 1.14  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.13  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.12  2000/08/01 14:51:50  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.11  2000/01/10 16:36:20  rgb
 * Ditch last of EME option flags, including initiator.
 *
 * Revision 1.10  1999/12/07 18:16:22  rgb
 * Fixed comments at end of #endif lines.
 *
 * Revision 1.9  1999/04/11 00:28:57  henry
 * GPL boilerplate
 *
 * Revision 1.8  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.7  1999/01/26 02:06:00  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 *
 * Revision 1.6  1999/01/22 15:22:05  rgb
 * Re-enable IV in the espblkrply_edata structure to avoid breaking pluto
 * until pluto can be fixed properly.
 *
 * Revision 1.5  1999/01/22 06:18:16  rgb
 * Updated macro comments.
 * Added key schedule types to support algorithm switch code.
 *
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
