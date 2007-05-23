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
