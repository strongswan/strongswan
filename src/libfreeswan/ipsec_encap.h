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
 * RCSID $Id$
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
