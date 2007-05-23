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
