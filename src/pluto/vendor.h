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
 * RCSID $Id: vendor.h,v 1.30 2006/04/12 16:44:28 as Exp $
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
  VID_STRONGSWAN		= 34,
  VID_STRONGSWAN_2_2_0		= 35,
  VID_STRONGSWAN_2_2_1		= 36,
  VID_STRONGSWAN_2_2_2		= 37,
  VID_STRONGSWAN_2_3_0		= 38,
  VID_STRONGSWAN_2_3_1		= 39,
  VID_STRONGSWAN_2_3_2		= 40,
  VID_STRONGSWAN_2_4_0		= 41,
  VID_STRONGSWAN_2_4_1		= 42,
  VID_STRONGSWAN_2_4_2		= 43,
  VID_STRONGSWAN_2_4_3		= 44,
  VID_STRONGSWAN_2_4_4		= 45,
  VID_STRONGSWAN_2_5_0		= 46,
  VID_STRONGSWAN_2_5_1		= 47,
  VID_STRONGSWAN_2_5_2		= 48,
  VID_STRONGSWAN_2_5_3		= 49,
  VID_STRONGSWAN_2_5_4		= 50,
  VID_STRONGSWAN_2_5_5		= 51,
  VID_STRONGSWAN_2_5_6		= 52,
  VID_STRONGSWAN_2_5_7		= 53,
  VID_STRONGSWAN_2_6_0		= 54,
  VID_STRONGSWAN_2_6_1		= 55,
  VID_STRONGSWAN_2_6_2		= 56,
  VID_STRONGSWAN_2_6_3		= 57,
  VID_STRONGSWAN_2_6_4		= 58,
  VID_STRONGSWAN_2_7_0		= 59,
  VID_STRONGSWAN_2_7_1		= 60,
  VID_STRONGSWAN_2_7_2		= 61,
  VID_STRONGSWAN_2_7_3		= 62,
  VID_STRONGSWAN_2_8_0		= 63,
  VID_STRONGSWAN_2_8_1		= 64,
  VID_STRONGSWAN_2_8_2		= 65,
  VID_STRONGSWAN_2_8_3		= 66,

  VID_STRONGSWAN_4_0_0		= 70,
  VID_STRONGSWAN_4_0_1		= 71,
  VID_STRONGSWAN_4_0_2		= 72,
  VID_STRONGSWAN_4_0_3		= 73,
  VID_STRONGSWAN_4_0_4		= 74,
  VID_STRONGSWAN_4_0_5		= 75,
  VID_STRONGSWAN_4_0_6		= 76,
  VID_STRONGSWAN_4_0_7		= 77,

  /* 101 - 200 : NAT-Traversal */
  VID_NATT_STENBERG_01		=101,
  VID_NATT_STENBERG_02		=102,
  VID_NATT_HUTTUNEN		=103,
  VID_NATT_HUTTUNEN_ESPINUDP	=104,
  VID_NATT_IETF_00		=105,
  VID_NATT_IETF_02_N		=106,
  VID_NATT_IETF_02		=107,
  VID_NATT_IETF_03		=108,
  VID_NATT_RFC			=109,

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

