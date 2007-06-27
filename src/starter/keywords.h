/* strongSwan keywords
 * Copyright (C) 2005 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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
 * RCSID $Id: keywords.h,v 1.8 2006/04/17 10:30:27 as Exp $
 */

#ifndef _KEYWORDS_H_
#define _KEYWORDS_H_

typedef enum {
    /* config setup keywords */
    KW_INTERFACES,
    KW_DUMPDIR,
    KW_CHARONSTART,
    KW_PLUTOSTART,

    /* pluto/charon keywords */
    KW_PLUTODEBUG,
    KW_CHARONDEBUG,
    KW_PREPLUTO,
    KW_POSTPLUTO,
    KW_UNIQUEIDS,
    KW_OVERRIDEMTU,
    KW_CRLCHECKINTERVAL,
    KW_CACHECRLS,
    KW_STRICTCRLPOLICY,
    KW_NOCRSEND,
    KW_NAT_TRAVERSAL,
    KW_KEEP_ALIVE,
    KW_VIRTUAL_PRIVATE,
    KW_EAPDIR,
    KW_PKCS11MODULE,
    KW_PKCS11KEEPSTATE,
    KW_PKCS11PROXY,

#define KW_PLUTO_FIRST	KW_PLUTODEBUG
#define KW_PLUTO_LAST	KW_PKCS11PROXY

    /* KLIPS keywords */
    KW_KLIPSDEBUG,
    KW_FRAGICMP,
    KW_PACKETDEFAULT,
    KW_HIDETOS,

#define KW_KLIPS_FIRST	KW_KLIPSDEBUG
#define KW_KLIPS_LAST	KW_HIDETOS

#define KW_SETUP_FIRST	KW_INTERFACES
#define KW_SETUP_LAST	KW_HIDETOS

    /* conn section keywords */
    KW_CONN_NAME,
    KW_CONN_SETUP,
    KW_KEYEXCHANGE,
    KW_TYPE,
    KW_PFS,
    KW_COMPRESS,
    KW_AUTH,
    KW_AUTHBY,
    KW_EAP,
    KW_IKELIFETIME,
    KW_KEYLIFE,
    KW_REKEYMARGIN,
    KW_KEYINGTRIES,
    KW_REKEYFUZZ,
    KW_REKEY,
    KW_REAUTH,
    KW_IKE,
    KW_ESP,
    KW_PFSGROUP,
    KW_DPDDELAY,
    KW_DPDTIMEOUT,
    KW_DPDACTION,
    KW_MODECONFIG,
    KW_XAUTH,

#define KW_CONN_FIRST	KW_CONN_SETUP
#define KW_CONN_LAST	KW_XAUTH

   /* ca section keywords */
    KW_CA_NAME,
    KW_CA_SETUP,
    KW_CACERT,
    KW_LDAPHOST,
    KW_LDAPBASE,
    KW_CRLURI,
    KW_CRLURI2,
    KW_OCSPURI,
    KW_OCSPURI2,

#define KW_CA_FIRST	KW_CA_SETUP
#define KW_CA_LAST	KW_OCSPURI2

   /* end keywords */
    KW_HOST,
    KW_NEXTHOP,
    KW_SUBNET,
    KW_SUBNETWITHIN,
    KW_PROTOPORT,
    KW_SOURCEIP,
    KW_NATIP,
    KW_FIREWALL,
    KW_HOSTACCESS,
    KW_ALLOWANY,
    KW_UPDOWN,
    KW_ID,
    KW_RSASIGKEY,
    KW_CERT,
    KW_SENDCERT,
    KW_CA,
    KW_GROUPS,
    KW_IFACE,

#define KW_END_FIRST	KW_HOST
#define KW_END_LAST	KW_IFACE

   /* left end keywords */
    KW_LEFT,
    KW_LEFTNEXTHOP,
    KW_LEFTSUBNET,
    KW_LEFTSUBNETWITHIN,
    KW_LEFTPROTOPORT,
    KW_LEFTSOURCEIP,
    KW_LEFTNATIP,
    KW_LEFTFIREWALL,
    KW_LEFTHOSTACCESS,
    KW_LEFTALLOWANY,
    KW_LEFTUPDOWN,
    KW_LEFTID,
    KW_LEFTRSASIGKEY,
    KW_LEFTCERT,
    KW_LEFTSENDCERT,
    KW_LEFTCA,
    KW_LEFTGROUPS,

#define KW_LEFT_FIRST	KW_LEFT
#define KW_LEFT_LAST	KW_LEFTGROUPS

   /* right end keywords */
    KW_RIGHT,
    KW_RIGHTNEXTHOP,
    KW_RIGHTSUBNET,
    KW_RIGHTSUBNETWITHIN,
    KW_RIGHTPROTOPORT,
    KW_RIGHTSOURCEIP,
    KW_RIGHTNATIP,
    KW_RIGHTFIREWALL,
    KW_RIGHTHOSTACCESS,
    KW_RIGHTALLOWANY,
    KW_RIGHTUPDOWN,
    KW_RIGHTID,
    KW_RIGHTRSASIGKEY,
    KW_RIGHTCERT,
    KW_RIGHTSENDCERT,
    KW_RIGHTCA,
    KW_RIGHTGROUPS,

#define KW_RIGHT_FIRST	KW_RIGHT
#define KW_RIGHT_LAST	KW_RIGHTGROUPS

    /* general section keywords */
    KW_ALSO,
    KW_AUTO

} kw_token_t;

#endif /* _KEYWORDS_H_ */

