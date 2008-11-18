/* FreeS/WAN ISAKMP VendorID
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
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

#ifndef _VENDOR_H_
#define _VENDOR_H_

enum known_vendorid {
/* 1 - 100 : Implementation names */
  VID_OPENPGP			=  1,
  VID_KAME_RACOON		=  2,
  VID_MS_NT5			=  3,
  VID_SSH_SENTINEL		=  4,
  VID_SSH_SENTINEL_1_1		=  5,
  VID_SSH_SENTINEL_1_2		=  6,
  VID_SSH_SENTINEL_1_3		=  7,
  VID_SSH_SENTINEL_1_4		=  8,
  VID_SSH_SENTINEL_1_4_1	=  9,
  VID_SSH_IPSEC_1_1_0		= 10,
  VID_SSH_IPSEC_1_1_1		= 11,
  VID_SSH_IPSEC_1_1_2		= 12,
  VID_SSH_IPSEC_1_2_1		= 13,
  VID_SSH_IPSEC_1_2_2		= 14,
  VID_SSH_IPSEC_2_0_0		= 15,
  VID_SSH_IPSEC_2_1_0		= 16,
  VID_SSH_IPSEC_2_1_1		= 17,
  VID_SSH_IPSEC_2_1_2		= 18,
  VID_SSH_IPSEC_3_0_0		= 19,
  VID_SSH_IPSEC_3_0_1		= 20,
  VID_SSH_IPSEC_4_0_0		= 21,
  VID_SSH_IPSEC_4_0_1		= 22,
  VID_SSH_IPSEC_4_1_0		= 23,
  VID_SSH_IPSEC_4_2_0		= 24,
  VID_CISCO_UNITY		= 25,
  VID_CISCO3K			= 26,
  VID_CISCO_IOS			= 27,
  VID_TIMESTEP			= 28,
  VID_SAFENET			= 29,
  VID_MACOSX			= 30,
  VID_OPENSWAN2			= 31,
  VID_NCP_SERVER		= 32,
  VID_NCP_CLIENT		= 33,
  VID_VISTA_AUTHIP		= 34,
  VID_VISTA_AUTHIP2		= 35,
  VID_VISTA_AUTHIP3		= 36,

  VID_STRONGSWAN		= 37,
  VID_STRONGSWAN_2_2_0		= 38,
  VID_STRONGSWAN_2_2_1		= 39,
  VID_STRONGSWAN_2_2_2		= 40,
  VID_STRONGSWAN_2_3_0		= 41,
  VID_STRONGSWAN_2_3_1		= 42,
  VID_STRONGSWAN_2_3_2		= 43,
  VID_STRONGSWAN_2_4_0		= 44,
  VID_STRONGSWAN_2_4_1		= 45,
  VID_STRONGSWAN_2_4_2		= 46,
  VID_STRONGSWAN_2_4_3		= 47,
  VID_STRONGSWAN_2_4_4		= 48,
  VID_STRONGSWAN_2_5_0		= 49,
  VID_STRONGSWAN_2_5_1		= 50,
  VID_STRONGSWAN_2_5_2		= 51,
  VID_STRONGSWAN_2_5_3		= 52,
  VID_STRONGSWAN_2_5_4		= 53,
  VID_STRONGSWAN_2_5_5		= 54,
  VID_STRONGSWAN_2_5_6		= 55,
  VID_STRONGSWAN_2_5_7		= 56,
  VID_STRONGSWAN_2_6_0		= 57,
  VID_STRONGSWAN_2_6_1		= 58,
  VID_STRONGSWAN_2_6_2		= 59,
  VID_STRONGSWAN_2_6_3		= 60,
  VID_STRONGSWAN_2_6_4		= 61,
  VID_STRONGSWAN_2_7_0		= 62,
  VID_STRONGSWAN_2_7_1		= 63,
  VID_STRONGSWAN_2_7_2		= 64,
  VID_STRONGSWAN_2_7_3		= 65,
  VID_STRONGSWAN_2_8_0		= 66,
  VID_STRONGSWAN_2_8_1		= 67,
  VID_STRONGSWAN_2_8_2		= 68,
  VID_STRONGSWAN_2_8_3		= 69,
  VID_STRONGSWAN_2_8_4		= 70,
  VID_STRONGSWAN_2_8_5		= 71,
  VID_STRONGSWAN_2_8_6		= 72,
  VID_STRONGSWAN_2_8_7		= 73,
  VID_STRONGSWAN_2_8_8		= 74,

  VID_STRONGSWAN_4_0_0		= 80,
  VID_STRONGSWAN_4_0_1		= 81,
  VID_STRONGSWAN_4_0_2		= 82,
  VID_STRONGSWAN_4_0_3		= 83,
  VID_STRONGSWAN_4_0_4		= 84,
  VID_STRONGSWAN_4_0_5		= 85,
  VID_STRONGSWAN_4_0_6		= 86,
  VID_STRONGSWAN_4_0_7		= 87,
  VID_STRONGSWAN_4_1_0		= 88,
  VID_STRONGSWAN_4_1_1		= 89,
  VID_STRONGSWAN_4_1_2		= 90,
  VID_STRONGSWAN_4_1_3		= 91,
  VID_STRONGSWAN_4_1_4		= 92,
  VID_STRONGSWAN_4_1_5		= 93,
  VID_STRONGSWAN_4_1_6		= 94,
  VID_STRONGSWAN_4_1_7		= 95,
  VID_STRONGSWAN_4_1_8		= 96,
  VID_STRONGSWAN_4_1_9		= 97,
  VID_STRONGSWAN_4_1_10		= 98,
  VID_STRONGSWAN_4_1_11		= 99,

  VID_STRONGSWAN_4_2_0		=100,
  VID_STRONGSWAN_4_2_1		=101,
  VID_STRONGSWAN_4_2_2		=102,
  VID_STRONGSWAN_4_2_3		=103,
  VID_STRONGSWAN_4_2_4		=104,
  VID_STRONGSWAN_4_2_5		=105,
  VID_STRONGSWAN_4_2_6		=106,
  VID_STRONGSWAN_4_2_7		=107,
  VID_STRONGSWAN_4_2_8		=108,
  VID_STRONGSWAN_4_2_9		=109,

  /* 101 - 200 : NAT-Traversal */
  VID_NATT_STENBERG_01		=151,
  VID_NATT_STENBERG_02		=152,
  VID_NATT_HUTTUNEN		=153,
  VID_NATT_HUTTUNEN_ESPINUDP	=154,
  VID_NATT_IETF_00		=155,
  VID_NATT_IETF_02_N		=156,
  VID_NATT_IETF_02		=157,
  VID_NATT_IETF_03		=158,
  VID_NATT_RFC			=159,

  /* 201 - 300 : Misc */
  VID_MISC_XAUTH		=201,
  VID_MISC_DPD			=202,
  VID_MISC_HEARTBEAT_NOTIFY	=203,
  VID_MISC_FRAGMENTATION	=204,
  VID_INITIAL_CONTACT		=205,
  VID_CISCO3K_FRAGMENTATION	=206
};

void init_vendorid(void);

struct msg_digest;
void handle_vendorid (struct msg_digest *md, const char *vid, size_t len);

bool out_vendorid (u_int8_t np, pb_stream *outs, enum known_vendorid vid);

#endif /* _VENDOR_H_ */

