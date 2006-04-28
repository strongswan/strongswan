/*
 * Definitions relevant to IPSEC transformations
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
 * RCSID $Id: ipsec_xform.h,v 1.3 2004/09/29 22:26:13 as Exp $
 */

#ifndef _IPSEC_XFORM_H_

#include <freeswan.h>
#include "ipsec_policy.h"

#define XF_NONE			0	/* No transform set */
#define XF_IP4			1	/* IPv4 inside IPv4 */
#define XF_AHMD5		2	/* AH MD5 */
#define XF_AHSHA		3	/* AH SHA */
#define XF_ESP3DES		5	/* ESP DES3-CBC */
#define XF_AHHMACMD5		6	/* AH-HMAC-MD5 with opt replay prot */
#define XF_AHHMACSHA1		7	/* AH-HMAC-SHA1 with opt replay prot */
#define XF_ESP3DESMD5		9	/* triple DES, HMAC-MD-5, 128-bits of authentication */
#define	XF_ESP3DESMD596		10	/* triple DES, HMAC-MD-5, 96-bits of authentication */
#define	XF_ESPNULLMD596		12	/* NULL, HMAC-MD-5 with 96-bits of authentication */
#define	XF_ESPNULLSHA196	13	/* NULL, HMAC-SHA-1 with 96-bits of authentication */
#define	XF_ESP3DESSHA196	14	/* triple DES, HMAC-SHA-1, 96-bits of authentication */
#define XF_IP6			15	/* IPv6 inside IPv6 */
#define XF_COMPDEFLATE		16	/* IPCOMP deflate */

#define XF_CLR			126	/* Clear SA table */
#define XF_DEL			127	/* Delete SA */

#define XFT_AUTH		0x0001
#define XFT_CONF		0x0100

/* available if CONFIG_IPSEC_DEBUG is defined */
#define DB_XF_INIT		0x0001

#define PROTO2TXT(x) \
	(x) == IPPROTO_AH ? "AH" : \
	(x) == IPPROTO_ESP ? "ESP" : \
	(x) == IPPROTO_IPIP ? "IPIP" : \
	(x) == IPPROTO_COMP ? "COMP" : \
	"UNKNOWN_proto"
static inline const char *enc_name_id (unsigned id) {
	static char buf[16];
	snprintf(buf, sizeof(buf), "_ID%d", id);
	return buf;
}
static inline const char *auth_name_id (unsigned id) {
	static char buf[16];
	snprintf(buf, sizeof(buf), "_ID%d", id);
	return buf;
}
#define IPS_XFORM_NAME(x) \
	PROTO2TXT((x)->ips_said.proto), \
	(x)->ips_said.proto == IPPROTO_COMP ? \
		((x)->ips_encalg == SADB_X_CALG_DEFLATE ? \
		 "_DEFLATE" : "_UNKNOWN_comp") : \
	(x)->ips_encalg == ESP_NONE ? "" : \
	(x)->ips_encalg == ESP_3DES ? "_3DES" : \
	(x)->ips_encalg == ESP_AES ? "_AES" : \
	(x)->ips_encalg == ESP_SERPENT ? "_SERPENT" : \
	(x)->ips_encalg == ESP_TWOFISH ? "_TWOFISH" : \
	enc_name_id(x->ips_encalg)/* "_UNKNOWN_encr" */, \
	(x)->ips_authalg == AH_NONE ? "" : \
	(x)->ips_authalg == AH_MD5 ? "_HMAC_MD5" : \
	(x)->ips_authalg == AH_SHA ? "_HMAC_SHA1" : \
	(x)->ips_authalg == AH_SHA2_256 ? "_HMAC_SHA2_256" : \
	(x)->ips_authalg == AH_SHA2_384 ? "_HMAC_SHA2_384" : \
	(x)->ips_authalg == AH_SHA2_512 ? "_HMAC_SHA2_512" : \
	auth_name_id(x->ips_authalg) /* "_UNKNOWN_auth" */ \

#define _IPSEC_XFORM_H_
#endif /* _IPSEC_XFORM_H_ */

/*
 * $Log: ipsec_xform.h,v $
 * Revision 1.3  2004/09/29 22:26:13  as
 * included ipsec_policy.h
 *
 * Revision 1.2  2004/03/22 21:53:18  as
 * merged alg-0.8.1 branch with HEAD
 *
 * Revision 1.1.4.1  2004/03/16 09:48:18  as
 * alg-0.8.1rc12 patch merged
 *
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.36  2002/04/24 07:36:48  mcr
 * Moved from ./klips/net/ipsec/ipsec_xform.h,v
 *
 * Revision 1.35  2001/11/26 09:23:51  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.33.2.1  2001/09/25 02:24:58  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	sa(tdb) manipulation functions renamed and moved to ipsec_sa.c
 * 	ipsec_xform.c removed. header file still contains useful things.
 *
 * Revision 1.34  2001/11/06 19:47:17  rgb
 * Changed lifetime_packets to uint32 from uint64.
 *
 * Revision 1.33  2001/09/08 21:13:34  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.32  2001/07/06 07:40:01  rgb
 * Reformatted for readability.
 * Added inbound policy checking fields for use with IPIP SAs.
 *
 * Revision 1.31  2001/06/14 19:35:11  rgb
 * Update copyright date.
 *
 * Revision 1.30  2001/05/30 08:14:03  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.29  2001/01/30 23:42:47  rgb
 * Allow pfkey msgs from pid other than user context required for ACQUIRE
 * and subsequent ADD or UDATE.
 *
 * Revision 1.28  2000/11/06 04:30:40  rgb
 * Add Svenning's adaptive content compression.
 *
 * Revision 1.27  2000/09/19 00:38:25  rgb
 * Fixed algorithm name bugs introduced for ipcomp.
 *
 * Revision 1.26  2000/09/17 21:36:48  rgb
 * Added proto2txt macro.
 *
 * Revision 1.25  2000/09/17 18:56:47  rgb
 * Added IPCOMP support.
 *
 * Revision 1.24  2000/09/12 19:34:12  rgb
 * Defined XF_IP6 from Gerhard for ipv6 tunnel support.
 *
 * Revision 1.23  2000/09/12 03:23:14  rgb
 * Cleaned out now unused tdb_xform and tdb_xdata members of struct tdb.
 *
 * Revision 1.22  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.21  2000/09/01 18:32:43  rgb
 * Added (disabled) sensitivity members to tdb struct.
 *
 * Revision 1.20  2000/08/30 05:31:01  rgb
 * Removed all the rest of the references to tdb_spi, tdb_proto, tdb_dst.
 * Kill remainder of tdb_xform, tdb_xdata, xformsw.
 *
 * Revision 1.19  2000/08/01 14:51:52  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.18  2000/01/21 06:17:45  rgb
 * Tidied up spacing.
 *
 * Revision 1.17  1999/11/17 15:53:40  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.16  1999/10/16 04:23:07  rgb
 * Add stats for replaywin_errs, replaywin_max_sequence_difference,
 * authentication errors, encryption size errors, encryption padding
 * errors, and time since last packet.
 *
 * Revision 1.15  1999/10/16 00:29:11  rgb
 * Added SA lifetime packet counting variables.
 *
 * Revision 1.14  1999/10/01 00:04:14  rgb
 * Added tdb structure locking.
 * Add function to initialize tdb hash table.
 *
 * Revision 1.13  1999/04/29 15:20:57  rgb
 * dd return values to init and cleanup functions.
 * Eliminate unnessessary usage of tdb_xform member to further switch
 * away from the transform switch to the algorithm switch.
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate parameter sanity checking.
 * Add a parameter to tdbcleanup to be able to delete a class of SAs.
 *
 * Revision 1.12  1999/04/15 15:37:25  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.9.2.2  1999/04/13 20:35:57  rgb
 * Fix spelling mistake in comment.
 *
 * Revision 1.9.2.1  1999/03/30 17:13:52  rgb
 * Extend struct tdb to support pfkey.
 *
 * Revision 1.11  1999/04/11 00:29:01  henry
 * GPL boilerplate
 *
 * Revision 1.10  1999/04/06 04:54:28  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.9  1999/01/26 02:09:31  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 * Removed dead code.
 *
 * Revision 1.8  1999/01/22 06:29:35  rgb
 * Added algorithm switch code.
 * Cruft clean-out.
 *
 * Revision 1.7  1998/11/10 05:37:35  rgb
 * Add support for SA direction flag.
 *
 * Revision 1.6  1998/10/19 14:44:29  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.5  1998/08/12 00:12:30  rgb
 * Added macros for new xforms.  Added prototypes for new xforms.
 *
 * Revision 1.4  1998/07/28 00:04:20  rgb
 * Add macro for clearing the SA table.
 *
 * Revision 1.3  1998/07/14 18:06:46  rgb
 * Added #ifdef __KERNEL__ directives to restrict scope of header.
 *
 * Revision 1.2  1998/06/23 03:02:19  rgb
 * Created a prototype for ipsec_tdbcleanup when it was moved from
 * ipsec_init.c.
 *
 * Revision 1.1  1998/06/18 21:27:51  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.4  1998/06/11 05:55:31  rgb
 * Added transform version string pointer to xformsw structure definition.
 * Added extern declarations for transform version strings.
 *
 * Revision 1.3  1998/05/18 22:02:54  rgb
 * Modify the *_zeroize function prototypes to include one parameter.
 *
 * Revision 1.2  1998/04/21 21:29:08  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:06:14  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:06  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:24:48  ji
 * Added ESP-3DES-MD5-96
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Added new transforms.
 *
 * Revision 0.3  1996/11/20 14:39:04  ji
 * Minor cleanups.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
