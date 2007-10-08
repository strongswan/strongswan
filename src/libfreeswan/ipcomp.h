/*
 * IPCOMP zlib interface code.
 * Copyright (C) 2000  Svenning Soerensen <svenning@post5.tele.dk>
 * Copyright (C) 2000, 2001  Richard Guy Briggs <rgb@conscoop.ottawa.on.ca>
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

 RCSID $Id$

 */

/* SSS */

#ifndef _IPCOMP_H
#define _IPCOMP_H

/* Prefix all global deflate symbols with "ipcomp_" to avoid collisions with ppp_deflate & ext2comp */
#ifndef IPCOMP_PREFIX
#define IPCOMP_PREFIX
#endif /* IPCOMP_PREFIX */

#ifndef IPPROTO_COMP
#define IPPROTO_COMP 108
#endif /* IPPROTO_COMP */

#ifdef CONFIG_IPSEC_DEBUG
extern int sysctl_ipsec_debug_ipcomp;
#endif /* CONFIG_IPSEC_DEBUG */

struct ipcomphdr {			/* IPCOMP header */
    __u8    ipcomp_nh;		/* Next header (protocol) */
    __u8    ipcomp_flags;	/* Reserved, must be 0 */
    __u16   ipcomp_cpi;		/* Compression Parameter Index */
};

extern struct inet_protocol comp_protocol;
extern int sysctl_ipsec_debug_ipcomp;

#define IPCOMP_UNCOMPRESSABLE     0x000000001
#define IPCOMP_COMPRESSIONERROR   0x000000002
#define IPCOMP_PARMERROR          0x000000004
#define IPCOMP_DECOMPRESSIONERROR 0x000000008

#define IPCOMP_ADAPT_INITIAL_TRIES	8
#define IPCOMP_ADAPT_INITIAL_SKIP	4
#define IPCOMP_ADAPT_SUBSEQ_TRIES	2
#define IPCOMP_ADAPT_SUBSEQ_SKIP	8

/* Function prototypes */
struct sk_buff *skb_compress(struct sk_buff *skb, struct ipsec_sa *ips, unsigned int *flags);
struct sk_buff *skb_decompress(struct sk_buff *skb, struct ipsec_sa *ips, unsigned int *flags);

#endif /* _IPCOMP_H */
