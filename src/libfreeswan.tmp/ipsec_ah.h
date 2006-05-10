/*
 * Authentication Header declarations
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
 * RCSID $Id: ipsec_ah.h,v 1.2 2004/03/22 21:53:18 as Exp $
 */

#include "ipsec_md5h.h"
#include "ipsec_sha1.h"

#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif /* IPPROTO_AH */

#define AH_FLENGTH		12		/* size of fixed part */
#define AHMD5_KMAX		64		/* MD5 max 512 bits key */
#define AHMD5_AMAX		12		/* MD5 96 bits of authenticator */

#define AHMD596_KLEN		16		/* MD5 128 bits key */
#define AHSHA196_KLEN		20		/* SHA1 160 bits key */

#define AHMD596_ALEN    	16		/* MD5 128 bits authentication length */
#define AHSHA196_ALEN		20		/* SHA1 160 bits authentication length */

#define AHMD596_BLKLEN  	64		/* MD5 block length */
#define AHSHA196_BLKLEN 	64		/* SHA1 block length */
#define AHSHA2_256_BLKLEN 	64		/* SHA2-256 block length */
#define AHSHA2_384_BLKLEN 	128 		/* SHA2-384 block length (?) */
#define AHSHA2_512_BLKLEN 	128		/* SHA2-512 block length */

#define AH_BLKLEN_MAX 		128		/* keep up to date! */

#define AH_AMAX         	AHSHA196_ALEN   /* keep up to date! */
#define AHHMAC_HASHLEN  	12              /* authenticator length of 96bits */
#define AHHMAC_RPLLEN   	4               /* 32 bit replay counter */

#define DB_AH_PKTRX		0x0001
#define DB_AH_PKTRX2		0x0002
#define DB_AH_DMP		0x0004
#define DB_AH_IPSA		0x0010
#define DB_AH_XF		0x0020
#define DB_AH_INAU		0x0040
#define DB_AH_REPLAY		0x0100

#ifdef __KERNEL__

/* General HMAC algorithm is described in RFC 2104 */

#define		HMAC_IPAD	0x36
#define		HMAC_OPAD	0x5C

struct md5_ctx {
	MD5_CTX ictx;		/* context after H(K XOR ipad) */
	MD5_CTX	octx;		/* context after H(K XOR opad) */
};

struct sha1_ctx {
	SHA1_CTX ictx;		/* context after H(K XOR ipad) */
	SHA1_CTX octx;		/* context after H(K XOR opad) */
};

struct auth_alg {
	void (*init)(void *ctx);
	void (*update)(void *ctx, unsigned char *bytes, __u32 len);
	void (*final)(unsigned char *hash, void *ctx);
	int hashlen;
};

extern struct inet_protocol ah_protocol;

struct options;

extern int 
ah_rcv(struct sk_buff *skb,
       struct device *dev,
       struct options *opt, 
       __u32 daddr,
       unsigned short len,
       __u32 saddr,
       int redo,
       struct inet_protocol *protocol);

struct ahhdr				/* Generic AH header */
{
	__u8	ah_nh;			/* Next header (protocol) */
	__u8	ah_hl;			/* AH length, in 32-bit words */
	__u16	ah_rv;			/* reserved, must be 0 */
	__u32	ah_spi;			/* Security Parameters Index */
        __u32   ah_rpl;                 /* Replay prevention */
	__u8	ah_data[AHHMAC_HASHLEN];/* Authentication hash */
};
#define AH_BASIC_LEN 8      /* basic AH header is 8 bytes, nh,hl,rv,spi
			     * and the ah_hl, says how many bytes after that
			     * to cover. */


#ifdef CONFIG_IPSEC_DEBUG
extern int debug_ah;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_ah.h,v $
 * Revision 1.2  2004/03/22 21:53:18  as
 * merged alg-0.8.1 branch with HEAD
 *
 * Revision 1.1.4.1  2004/03/16 09:48:18  as
 * alg-0.8.1rc12 patch merged
 *
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.20  2003/02/06 02:21:34  rgb
 *
 * Moved "struct auth_alg" from ipsec_rcv.c to ipsec_ah.h .
 * Changed "struct ah" to "struct ahhdr" and "struct esp" to "struct esphdr".
 * Removed "#ifdef INBOUND_POLICY_CHECK_eroute" dead code.
 *
 * Revision 1.19  2002/09/16 21:19:13  mcr
 * 	fixes for west-ah-icmp-01 - length of AH header must be
 * 	calculated properly, and next_header field properly copied.
 *
 * Revision 1.18  2002/05/14 02:37:02  rgb
 * Change reference from _TDB to _IPSA.
 *
 * Revision 1.17  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_ah.h,v
 *
 * Revision 1.16  2002/02/20 01:27:06  rgb
 * Ditched a pile of structs only used by the old Netlink interface.
 *
 * Revision 1.15  2001/12/11 02:35:57  rgb
 * Change "struct net_device" to "struct device" for 2.2 compatibility.
 *
 * Revision 1.14  2001/11/26 09:23:47  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.13.2.1  2001/09/25 02:18:24  mcr
 * 	replace "struct device" with "struct netdevice"
 *
 * Revision 1.13  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.12  2000/09/12 03:21:20  rgb
 * Cleared out unused htonq.
 *
 * Revision 1.11  2000/09/08 19:12:55  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.10  2000/01/21 06:13:10  rgb
 * Tidied up spacing.
 * Added macros for HMAC padding magic numbers.(kravietz)
 *
 * Revision 1.9  1999/12/07 18:16:23  rgb
 * Fixed comments at end of #endif lines.
 *
 * Revision 1.8  1999/04/11 00:28:56  henry
 * GPL boilerplate
 *
 * Revision 1.7  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.6  1999/01/26 02:06:01  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 *
 * Revision 1.5  1999/01/22 06:17:49  rgb
 * Updated macro comments.
 * Added context types to support algorithm switch code.
 * 64-bit clean-up -- converting 'u long long' to __u64.
 *
 * Revision 1.4  1998/07/14 15:54:56  rgb
 * Add #ifdef __KERNEL__ to protect kernel-only structures.
 *
 * Revision 1.3  1998/06/30 18:05:16  rgb
 * Comment out references to htonq.
 *
 * Revision 1.2  1998/06/25 19:33:46  rgb
 * Add prototype for protocol receive function.
 * Rearrange for more logical layout.
 *
 * Revision 1.1  1998/06/18 21:27:43  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
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
 * Revision 1.2  1998/04/12 22:03:17  rgb
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
 * Revision 1.1  1998/04/09 03:05:55  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Added definitions for new AH transforms.
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
